#!/usr/bin/env bash
# Build a self-contained delivery bundle for the E64 WS development environment.
#
# The bundle intentionally excludes vendor firmware. It ships the tooling, the
# documentation, and a fetch script that downloads the public vendor image and
# verifies its published SHA-256 before extraction.
#
# Usage: tools/package_dev_env.sh [output-dir]   (default: dist)

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
outdir="${1:-$root/dist}"
stamp="$(date +%Y%m%d)"
name="e64-dev-env-$stamp"
stage="$outdir/$name"

command -v tar >/dev/null || { echo "tar not found" >&2; exit 1; }

rm -rf "$stage"
mkdir -p "$stage/tools/ghidra" "$stage/docs" "$stage/integrations"

# Executable tooling and reference clients.
cp "$root"/tools/*.py "$stage/tools/"
cp "$root"/tools/*.sh "$stage/tools/"
cp "$root"/tools/*.js "$stage/tools/" 2>/dev/null || true
cp "$root"/tools/requirements.txt "$stage/tools/"
cp "$root"/tools/ghidra/*.sh "$root"/tools/ghidra/*.java "$stage/tools/ghidra/" 2>/dev/null || true

# Documentation: the whole docs tree, minus generated data.
cp "$root"/docs/*.md "$stage/docs/"
if [[ -d "$root/docs/generated" ]]; then
    mkdir -p "$stage/docs/generated"
    cp -R "$root/docs/generated/." "$stage/docs/generated/" 2>/dev/null || true
fi

cp "$root/README.md" "$root/CONTRIBUTING.md" "$root/SECURITY.md" "$stage/" 2>/dev/null || true

# Integration adapters are small and useful for app development.
cp -R "$root/integrations/." "$stage/integrations/" 2>/dev/null || true

cat > "$stage/fetch_firmware.sh" <<'FETCH'
#!/usr/bin/env bash
# Download the public vendor firmware and verify the pinned digest.
set -euo pipefail

URL="https://downloads.mahlkoenig.de/Service/HEM-HSG-HMI-S01-V01.16-24.swu"
SHA="4659b140d2b871ad98f1c0b8d88351708c3dbe20e5c638a4e5339dce89f3b5a2"
DEST="${1:-.tools/firmware-1.16-24}"
IMG="${E64_SWU:-HEM-HSG-HMI-S01-V01.16-24.swu}"

mkdir -p "$DEST/raw"
if [[ ! -f "$IMG" ]]; then
    echo "Downloading $URL"
    curl -fL --retry 3 -o "$IMG" "$URL"
fi

actual="$(shasum -a 256 "$IMG" | awk '{print $1}')"
if [[ "$actual" != "$SHA" ]]; then
    echo "SHA-256 mismatch: expected $SHA, got $actual" >&2
    exit 1
fi
echo "Firmware digest verified"

if [[ ! -f "$DEST/raw/sw-description" ]]; then
    ( cd "$DEST/raw" && bsdtar -xf "$OLDPWD/$IMG" )
fi

for pair in rootfs.ext2:images.standard.rootfs.ext2.gz \
            app_image.ext4:images.standard.app_image.ext4.gz \
            boot.vfat:images.standard.boot.vfat.gz; do
    out="${pair%%:*}"; src="${pair##*:}"
    [[ -f "$DEST/$out" ]] || gunzip -c "$DEST/raw/$src" > "$DEST/$out"
done

echo "Images ready under $DEST. Extract filesystems with e2fsprogs debugfs:"
echo "  debugfs -R 'rdump / $PWD/$DEST/rootfs-tree' $DEST/rootfs.ext2"
echo "  debugfs -R 'rdump / $PWD/$DEST/app-tree' $DEST/app_image.ext4"
FETCH
chmod +x "$stage/fetch_firmware.sh"

cat > "$stage/QUICKSTART.md" <<'QS'
# E64 WS development environment quickstart

1. `./fetch_firmware.sh` — downloads the public vendor image, verifies SHA-256,
   extracts the SWU and decompresses the partitions.
2. Extract the filesystems with `debugfs` (commands printed by the script).
3. `python3 -m venv .venv && .venv/bin/pip install -r tools/requirements.txt`
4. `tools/qemu_offline_www.sh up` — runs the real vendor web UI at
   http://127.0.0.1:18080/login.php.
5. `.venv/bin/python tools/e64ws_simulator.py --host 127.0.0.1 --port 9997
   --scale-port 8765 --http-port 8787` — simulated grinder for hardware
   behaviour.

Read `docs/OFFLINE_QEMU_HARNESS.md`, `docs/CUSTOM_APPS_DEV_ENV.md`, and
`docs/BOOT_AND_BRICK_SAFETY.md` before writing anything to a real machine.
QS

tar -czf "$outdir/$name.tar.gz" -C "$outdir" "$name"
shasum -a 256 "$outdir/$name.tar.gz" | tee "$outdir/$name.tar.gz.sha256"
echo "bundle: $outdir/$name.tar.gz"
