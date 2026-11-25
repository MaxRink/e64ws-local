#!/usr/bin/env bash
# Run the shipped E64 WS web UI (lighttpd + PHP-CGI from the extracted
# firmware) under QEMU user emulation.
#
# Scope: this is an offline development harness for the PHP/HTTP surface. It
# runs the vendor rootfs userland in a linux/arm/v7 container. It does not run
# the native HMI (NgxUiApp/libNgxUi), the ESP transport, the grinder motor, or
# the TLS listener, and it never contacts the vendor cloud or a real machine.
#
# Usage:
#   tools/qemu_offline_www.sh up        start (default)
#   tools/qemu_offline_www.sh status    show container state and probe /
#   tools/qemu_offline_www.sh logs      follow lighttpd/PHP logs
#   tools/qemu_offline_www.sh down      stop and remove the container
#
# Environment:
#   E64_FW_DIR         extracted firmware dir (default .tools/firmware-1.16-24)
#   E64_WWW_PORT       host port (default 18080)
#   E64_WWW_CONTAINER  container name (default e64-www)
#
# Prerequisites: docker with linux/arm/v7 emulation (OrbStack or similar) and
# an extracted image. See docs/REPRODUCTION.md for the extraction steps.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fw="${E64_FW_DIR:-$root/.tools/firmware-1.16-24}"
port="${E64_WWW_PORT:-18080}"
name="${E64_WWW_CONTAINER:-e64-www}"
image="${E64_WWW_IMAGE:-alpine}"

rootfs="$fw/rootfs-tree"
www="$fw/app-tree/www"

die() { echo "error: $*" >&2; exit 1; }

require_inputs() {
    command -v docker >/dev/null || die "docker not found"
    [[ -d "$rootfs" ]] || die "missing rootfs tree: $rootfs (run the extraction in docs/REPRODUCTION.md)"
    [[ -d "$www" ]] || die "missing app web root: $www"
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
}

# The vendor config enables TLS on :443 with keys from /db and redirects all
# HTTP to HTTPS. The offline harness keeps everything up to the TLS block so
# the FastCGI/PHP behaviour is unchanged, but drops TLS and the redirect.
write_config() {
    local dir="$root/.tools/offline-www"
    mkdir -p "$dir"
    awk '/^\$SERVER\["socket"\] == ":443"/{exit} {print}' \
        "$rootfs/etc/lighttpd/lighttpd.conf" > "$dir/lighttpd.conf"
    grep -q "fastcgi.server" "$dir/lighttpd.conf" \
        || die "generated config lost the fastcgi block"
    echo "$dir/lighttpd.conf"
}

cmd_up() {
    require_inputs
    local conf
    conf="$(write_config)"
    docker rm -f "$name" >/dev/null 2>&1 || true

    # /dev nodes are empty in the extracted image; bind the host's in read-only.
    docker run -d --name "$name" --platform linux/arm/v7 -p "$port:80" \
        -v "$rootfs:/rootfs" \
        -v "$www:/rootfs/usr/local/www:ro" \
        -v "$conf:/rootfs/etc/lighttpd/lighttpd.conf:ro" \
        -v /dev/null:/rootfs/dev/null \
        -v /dev/zero:/rootfs/dev/zero \
        -v /dev/urandom:/rootfs/dev/urandom \
        -v /dev/random:/rootfs/dev/random \
        "$image" chroot /rootfs /usr/sbin/lighttpd -D -f /etc/lighttpd/lighttpd.conf \
        >/dev/null

    for _ in $(seq 1 30); do
        if curl -fsS -o /dev/null "http://127.0.0.1:$port/login.php" 2>/dev/null; then
            echo "E64 WS web UI: http://127.0.0.1:$port/login.php"
            echo "REST entry:    http://127.0.0.1:$port/rest_api.php/"
            return 0
        fi
        sleep 1
    done
    echo "container started but the UI did not answer; recent logs:" >&2
    docker logs "$name" 2>&1 | tail -20 >&2
    return 1
}

cmd_down() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    echo "stopped $name"
}

cmd_status() {
    docker ps --filter "name=^/$name$" --format '{{.Names}} {{.Status}} {{.Ports}}' || true
    curl -s -o /dev/null -w "GET / -> %{http_code}\n" "http://127.0.0.1:$port/" || true
    curl -s -o /dev/null -w "GET /login.php -> %{http_code}\n" "http://127.0.0.1:$port/login.php" || true
}

case "${1:-up}" in
    up) cmd_up ;;
    down) cmd_down ;;
    status) cmd_status ;;
    logs) docker logs -f "$name" ;;
    *) die "usage: $0 [up|status|logs|down]" ;;
esac
