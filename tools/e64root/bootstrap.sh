#!/bin/sh
# One-command owner bootstrap: FW-01 root -> static dropbear -> owner key.
#
#   tools/e64root/bootstrap.sh --host 192.168.1.50 --yes
#
# Defaults to the vendor self-signed HTTPS certificate (explicit warning) and
# generates ~/.e64root/id_ed25519 on first use. It only acts on a grinder the
# owner controls.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOST=""
PORT=443
SSH_HOST=""
SSH_PORT=22
DAEMON_PORT=22
CA_FILE=""
YES=0
KEY="${E64ROOT_KEY:-$HOME/.e64root/id_ed25519}"
DROPBEAR="${E64ROOT_DROPBEAR:-$HERE/vendor/dropbear-armhf}"

usage() {
    cat <<EOF
usage: $0 --host HOST [--port 443] [--ssh-host HOST] [--ssh-port 22] --yes

One-command owner root/SSH install through FW-01 (the login.php injection).
It generates a key at ~/.e64root/id_ed25519 if none exists and uses the
bundled static ARMv7 dropbear.

Options:
  --host HOST        grinder hostname/IP (required)
  --port PORT        HTTPS port (default 443)
  --ssh-host HOST    host/forward to connect to after install (default: HOST)
  --ssh-port PORT    SSH connect port (default 22; QEMU often 22222)
  --daemon-port PORT guest dropbear listen port (default 22)
  --key PATH         owner private key (default ~/.e64root/id_ed25519)
  --dropbear PATH    static armhf dropbear (default vendor dropbear-armhf)
  --ca-file PATH     verify HTTPS against this certificate
  --yes              required: perform the change
  -h, --help         show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=${2:?}; shift 2 ;;
        --port) PORT=${2:?}; shift 2 ;;
        --ssh-host) SSH_HOST=${2:?}; shift 2 ;;
        --ssh-port) SSH_PORT=${2:?}; shift 2 ;;
        --daemon-port) DAEMON_PORT=${2:?}; shift 2 ;;
        --key) KEY=${2:?}; shift 2 ;;
        --dropbear) DROPBEAR=${2:?}; shift 2 ;;
        --ca-file) CA_FILE=${2:?}; shift 2 ;;
        --yes) YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$HOST" ]; then
    echo "--host is required" >&2
    usage >&2
    exit 2
fi
if [ "$YES" != 1 ]; then
    echo "refusing to change the grinder without --yes (inspect docs/ROOT_TOOL.md first)" >&2
    exit 1
fi
if [ ! -x "$DROPBEAR" ]; then
    echo "missing static dropbear: $DROPBEAR" >&2
    echo "read tools/e64root/vendor/README.md or pass --dropbear" >&2
    exit 1
fi

umask 077
mkdir -p "$(dirname -- "$KEY")"
chmod 700 "$(dirname -- "$KEY")"
if [ ! -f "$KEY" ]; then
    ssh-keygen -q -t ed25519 -f "$KEY" -N "" -C "e64root@$(hostname 2>/dev/null || echo owner)"
    echo "generated owner key: $KEY"
fi
if [ ! -f "$KEY.pub" ]; then
    ssh-keygen -y -f "$KEY" > "$KEY.pub"
fi

if [ -z "$CA_FILE" ]; then
    echo "warning: the vendor HTTPS certificate is self-signed; using --insecure" >&2
    echo "         pass --ca-file to verify it instead" >&2
fi

set -- ssh --host "$HOST" --port "$PORT" --via web \
    --dropbear "$DROPBEAR" --pubkey-file "$KEY.pub" --ssh-key "$KEY" \
    --daemon-port "$DAEMON_PORT" --ssh-wait 30 --yes
if [ -n "$SSH_HOST" ]; then
    set -- "$@" --ssh-host "$SSH_HOST"
fi
set -- "$@" --ssh-port "$SSH_PORT"
if [ -n "$CA_FILE" ]; then
    set -- "$@" --ca-file "$CA_FILE"
else
    set -- "$@" --insecure
fi

exec "$HERE/e64root" "$@"
