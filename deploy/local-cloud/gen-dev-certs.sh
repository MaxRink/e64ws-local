#!/bin/sh
# Generate development TLS material for the local-cloud skeleton.
#
# DEVELOPMENT ONLY.  These are throwaway keys for a laptop: nothing here is a
# vendor key, and nothing here should ever be trusted by a real grinder.  The
# real trust change is a deliberate, rollback-planned act on the device
# (docs/LOCAL_CLOUD_DESIGN.md §6/§7), not a script.
#
# What it creates, in the directory given as $1 (default: a fresh `mktemp -d`):
#
#   pki/device-ca.pem      local CA certificate  -> Caddyfile trust_pool
#   pki/device-ca.key      its private key       -> keep offline, never commit
#   certs/device-host.crt  server certificate for the compiled hostname,
#                          plus localhost/127.0.0.1 SANs for curl testing
#   certs/device-host.key
#   certs/device-client.crt  one EC P-521 client certificate (the firmware's
#                            curve - P-256 is rejected for the same key,
#                            CLOUD_TLS_INJECTION.md "Client identity")
#   certs/device-client.key
#
# Usage:
#   sh deploy/local-cloud/gen-dev-certs.sh            # fresh mktemp directory
#   sh deploy/local-cloud/gen-dev-certs.sh /tmp/lc    # writes into /tmp/lc
#
# The default used to be this script's own directory, i.e. deploy/local-cloud/
# in the working tree: a CA private key landed in the repository directory
# (`.gitignore`d, but one `git add -A` away from being committed, and readable
# by anything running as the same user).  The default is now a private
# temporary directory, printed at the end, and the whole run is under
# `umask 077` so every file it creates is owner-only even on an openssl build
# that does not tighten private-key permissions itself.
#
# The output directory is printed as `output directory: <path>` - pass that to
# `docker compose` as a bind mount, or copy certs/ and pki/ into
# deploy/local-cloud/ yourself if you really want them in the tree.
#
# Requires openssl 3 or newer (for -addext).  Offline: no network, no ACME.

set -eu

# Owner-only for everything this script creates, including the temp directory.
# Set before the first mkdir so the mode is on the directory, not added later.
umask 077

if [ "$#" -ge 1 ]; then
    out=$1
else
    # `${tmpdir%/}`: macOS sets TMPDIR with a trailing slash, which would print
    # a cosmetic double slash in the path below.
    tmpdir=${TMPDIR:-/tmp}
    out=$(mktemp -d "${tmpdir%/}/local-cloud-dev-certs.XXXXXX")
fi
mkdir -p "$out/certs" "$out/pki"

if [ -e "$out/pki/device-ca.key" ]; then
    echo "refusing to overwrite existing CA in $out/pki" >&2
    echo "delete $out/pki and $out/certs first if you really want new material" >&2
    exit 1
fi

days=365

# --- CA (EC P-256, matching the 826-byte slot the design asks for) ---------
openssl ecparam -name prime256v1 -genkey -noout -out "$out/pki/device-ca.key"
openssl req -x509 -new -key "$out/pki/device-ca.key" -days "$days" \
    -subj "/CN=local-cloud development CA" \
    -out "$out/pki/device-ca.pem"

# --- server certificate ----------------------------------------------------
sanfile=$(mktemp)
trap 'rm -f "$sanfile"' EXIT
cat >"$sanfile" <<'EXT'
subjectAltName=DNS:ngx-secured.sync.mahlkoenig.com,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
EXT

openssl ecparam -name prime256v1 -genkey -noout -out "$out/certs/device-host.key"
openssl req -new -key "$out/certs/device-host.key" \
    -subj "/CN=ngx-secured.sync.mahlkoenig.com" \
    -out "$out/certs/device-host.csr"
openssl x509 -req -in "$out/certs/device-host.csr" -days "$days" \
    -CA "$out/pki/device-ca.pem" -CAkey "$out/pki/device-ca.key" \
    -CAcreateserial -extfile "$sanfile" \
    -out "$out/certs/device-host.crt"

# --- one client certificate on the firmware's curve -----------------------
clientfile=$(mktemp)
trap 'rm -f "$sanfile" "$clientfile"' EXIT
cat >"$clientfile" <<'EXT'
extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE
EXT

openssl ecparam -name secp521r1 -genkey -noout -out "$out/certs/device-client.key"
openssl req -new -key "$out/certs/device-client.key" \
    -subj "/CN=grinder-local" -out "$out/certs/device-client.csr"
openssl x509 -req -in "$out/certs/device-client.csr" -days "$days" \
    -CA "$out/pki/device-ca.pem" -CAkey "$out/pki/device-ca.key" \
    -CAcreateserial -extfile "$clientfile" \
    -out "$out/certs/device-client.crt"

rm -f "$out/certs/device-host.csr" "$out/certs/device-client.csr"

echo "wrote:"
ls -1 "$out/pki/device-ca.pem" \
      "$out/certs/device-host.crt" "$out/certs/device-host.key" \
      "$out/certs/device-client.crt" "$out/certs/device-client.key"
echo
echo "output directory: $out"
echo "  (mode 0700, owner-only; nothing was written into the repository)"
echo
echo "client fingerprint (enrol it through the admin API):"
openssl x509 -in "$out/certs/device-client.crt" -noout -fingerprint -sha256 |
    sed 's/^.*=//'
echo
echo "development material only - do not trust it from a real device"
