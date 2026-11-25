// Minimal MQTT 3.1.1 broker with username/password authentication.
//
// Built as a static linux/arm binary for the grinder. Supports CONNECT auth,
// SUBSCRIBE, PUBLISH (QoS 0/1), retained messages, PING and DISCONNECT.
// TLS is intentionally out of scope: run it on a trusted segment or front it
// with a TLS terminator.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

type message struct {
	topic   string
	payload []byte
	qos     byte
	retain  bool
}

type client struct {
	conn     net.Conn
	id       string
	subs     []string
	mu       sync.Mutex
	writeMu  sync.Mutex
}

func (c *client) send(pkt []byte) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, _ = c.conn.Write(pkt)
}

type broker struct {
	mu       sync.RWMutex
	clients  map[*client]bool
	retained map[string]message
	users    map[string]string
}

func topicMatches(filter, topic string) bool {
	if filter == "#" {
		return true
	}
	if strings.HasSuffix(filter, "/#") {
		prefix := strings.TrimSuffix(filter, "#")
		return strings.HasPrefix(topic, prefix)
	}
	return filter == topic
}

func (b *broker) publish(m message) {
	if m.retain {
		b.mu.Lock()
		if len(m.payload) == 0 {
			delete(b.retained, m.topic)
		} else {
			b.retained[m.topic] = m
		}
		b.mu.Unlock()
	}
	b.mu.RLock()
	targets := make([]*client, 0, len(b.clients))
	for c := range b.clients {
		for _, f := range c.subs {
			if topicMatches(f, m.topic) {
				targets = append(targets, c)
				break
			}
		}
	}
	b.mu.RUnlock()
	for _, c := range targets {
		c.send(encodePublish(m, 0))
	}
}

func encodePublish(m message, packetID uint16) []byte {
	body := make([]byte, 0, len(m.topic)+len(m.payload)+4)
	body = append(body, byte(len(m.topic)>>8), byte(len(m.topic)))
	body = append(body, m.topic...)
	if m.qos > 0 {
		body = append(body, byte(packetID>>8), byte(packetID))
	}
	body = append(body, m.payload...)
	flags := byte(0x30) | (m.qos << 1)
	return append([]byte{flags}, append(encodeLength(len(body)), body...)...)
}

func encodeLength(n int) []byte {
	var out []byte
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		out = append(out, d)
		if n == 0 {
			return out
		}
	}
}

func readLength(r *bufio.Reader) (int, error) {
	mult, value := 1, 0
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(b&0x7f) * mult
		if b&0x80 == 0 {
			return value, nil
		}
		mult *= 128
	}
	return 0, fmt.Errorf("malformed length")
}

func (b *broker) handle(conn net.Conn) {
	defer conn.Close()
	c := &client{conn: conn}
	r := bufio.NewReader(conn)

	// CONNECT
	hdr, err := r.ReadByte()
	if err != nil || hdr>>4 != 1 {
		return
	}
	remaining, err := readLength(r)
	if err != nil {
		return
	}
	body := make([]byte, remaining)
	if _, err := io.ReadFull(r, body); err != nil {
		return
	}
	pos := 0
	plen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2 + plen
	pos++ // level
	flags := body[pos]
	pos += 3 // flags + keepalive
	cidLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	c.id = string(body[pos : pos+cidLen])
	pos += cidLen
	if flags&0x04 != 0 { // will
		wl := int(binary.BigEndian.Uint16(body[pos:]))
		pos += 2 + wl
		ml := int(binary.BigEndian.Uint16(body[pos:]))
		pos += 2 + ml
	}
	var username, password string
	if flags&0x80 != 0 {
		l := int(binary.BigEndian.Uint16(body[pos:]))
		pos += 2
		username = string(body[pos : pos+l])
		pos += l
	}
	if flags&0x40 != 0 {
		l := int(binary.BigEndian.Uint16(body[pos:]))
		pos += 2
		password = string(body[pos : pos+l])
	}
	if want, ok := b.users[username]; !ok || want != password {
		c.send([]byte{0x20, 0x02, 0x00, 0x05}) // not authorized
		log.Printf("auth failed user=%q client=%q", username, c.id)
		return
	}
	c.send([]byte{0x20, 0x02, 0x00, 0x00})
	log.Printf("connect user=%q client=%q", username, c.id)

	b.mu.Lock()
	b.clients[c] = true
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, c)
		b.mu.Unlock()
		log.Printf("disconnect client=%q", c.id)
	}()

	for {
		hdr, err := r.ReadByte()
		if err != nil {
			return
		}
		remaining, err := readLength(r)
		if err != nil {
			return
		}
		payload := make([]byte, remaining)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		switch hdr >> 4 {
		case 3: // PUBLISH
			qos := (hdr >> 1) & 3
			tl := int(binary.BigEndian.Uint16(payload))
			topic := string(payload[2 : 2+tl])
			rest := payload[2+tl:]
			var pid uint16
			if qos > 0 {
				pid = binary.BigEndian.Uint16(rest)
				rest = rest[2:]
			}
			m := message{topic: topic, payload: rest, qos: qos, retain: hdr&1 == 1}
			if qos == 1 {
				c.send([]byte{0x40, 0x02, byte(pid >> 8), byte(pid)})
			}
			b.publish(m)
		case 8: // SUBSCRIBE
			pid := binary.BigEndian.Uint16(payload)
			pos := 2
			var granted []byte
			for pos < len(payload) {
				l := int(binary.BigEndian.Uint16(payload[pos:]))
				pos += 2
				filter := string(payload[pos : pos+l])
				pos += l + 1
				c.subs = append(c.subs, filter)
				granted = append(granted, 0x01)
				b.mu.RLock()
				for t, m := range b.retained {
					if topicMatches(filter, t) {
						c.send(encodePublish(m, 0))
					}
				}
				b.mu.RUnlock()
			}
			resp := []byte{0x90, byte(2 + len(granted)), byte(pid >> 8), byte(pid)}
			c.send(append(resp, granted...))
		case 12: // PINGREQ
			c.send([]byte{0xD0, 0x00})
		case 14: // DISCONNECT
			return
		case 4, 5, 6, 7, 10, 11: // acks / unsubscribe: ignore
		default:
			log.Printf("unhandled packet type %d", hdr>>4)
		}
	}
}

func loadUsers(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("users file: %v", err)
	}
	users := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			users[parts[0]] = parts[1]
		}
	}
	return users
}

func main() {
	listen := flag.String("listen", ":1883", "listen address")
	usersFile := flag.String("users", "/storage/mqtt/users", "user:password file")
	flag.Parse()

	b := &broker{
		clients:  map[*client]bool{},
		retained: map[string]message{},
		users:    loadUsers(*usersFile),
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("mqttd listening on %s with %d user(s)", *listen, len(b.users))
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go b.handle(conn)
	}
}
