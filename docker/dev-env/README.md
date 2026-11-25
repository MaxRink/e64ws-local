# Development tools container

Everything needed to run the repository's analysis and virtual-device tooling,
without installing QEMU, e2fsprogs, Python and Node on the host.

The vendor firmware is **not** baked into the image. It is fetched at container
start by the repository's own digest-pinned script.

## Build

```sh
docker build -f docker/dev-env/Dockerfile -t e64-dev-env .
```

## Run

```sh
# interactive shell with the repository mounted
docker run --rm -it -v "$PWD:/work" -w /work e64-dev-env

# inside: fetch firmware, extract, run tests
./fetch_firmware.sh
debugfs -R 'rdump / /work/.tools/firmware-1.16-24/rootfs-tree' .tools/firmware-1.16-24/rootfs.ext2
python3 -m unittest discover -s tests -v

# boot the full virtual machine (QEMU system mode is inside the image)
tools/qemu_system_boot.sh prepare
tools/qemu_system_boot.sh run
```

The web UI of the virtual machine is reachable at
`http://localhost:18082/` and `https://localhost:18443/login.php`.

Running the *user-mode* harness (`tools/qemu_offline_www.sh`) requires Docker
inside the container, so it is normally run on the host instead.

## Contents

| Tool | Why |
|---|---|
| `qemu-system-arm` | Full-system boot of the vendor rootfs |
| `e2fsprogs` (`debugfs`, `mke2fs`) | Extract and patch ext2/ext4 images |
| `mtools` | Read the boot FAT partition |
| `python3` | Simulator, clients, test suites |
| `nodejs` | GBS Python/Node parity |
| `bsdtar`, `cpio` | SWU and initramfs handling |
| `rea-agents` | REA MCP server (Ghidra/JADX-driven analysis) for agents |

Ghidra, JADX and the vendor firmware are deliberately not in the image: Ghidra
is large and licence-sensitive, JADX is optional, and the firmware must be
fetched and verified by the user.
