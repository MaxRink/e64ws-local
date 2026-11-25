#!/usr/bin/env bash
# Generate a local CA, a server cert for the device-service hostname and a
# client cert (the grinder's mTLS identity).
set -euo pipefail
out="${1:-./certs}"
mkdir -p "$out"
cd "$out"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/CN=e64 local cloud CA" -keyout ca.key -out ca.crt >/dev/null 2>&1

cat > san.cnf <<'CONF'
[req]
distinguished_name=dn
req_extensions=ext
prompt=no
[dn]
CN=ngx-secured.sync.mahlkoenig.com
[ext]
subjectAltName=@alt
[alt]
DNS.1=ngx-secured.sync.mahlkoenig.com
DNS.2=localhost
IP.1=127.0.0.1
CONF

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -config san.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -extensions ext -extfile san.cnf -out server.crt >/dev/null 2>&1

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=e64 grinder client" >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -out client.crt >/dev/null 2>&1

rm -f server.csr client.csr
ls -1 ca.crt ca.key server.crt server.key client.crt client.key
