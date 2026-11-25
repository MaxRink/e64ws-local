# Rebuild harnesses

Durable copies of the build harnesses used for the reproducibility work in
[docs/REPRODUCIBILITY.md](../../docs/REPRODUCIBILITY.md). They originally lived
under `/tmp`, which does not survive a reboot.

Nothing here contains vendor code or keys. Every script builds from public
upstream sources (ESP-IDF, esp-hosted, Buildroot, BusyBox) plus a recovered
configuration.

## Contents

| Path | Purpose | Result |
|---|---|---|
| `esp-boot/` | ESP32 second-stage bootloader, ESP-IDF v5.0.0 | **26,848 / 26,848 bytes, sha256 `78027485…7304`, `cmp` clean** |
| `esp-app/` | ESP32 application, upstream-only reference build (esp-hosted `release/ng-v1.0.2` + protobuf-c v1.4.1) | 600,323 / 910,640 bytes = **65.92 %** coverage (window unstated); 2.49 % same-offset, 4.08 % same-VA |
| `esp-app/recon/` | Clean-room reconstruction of the 204 vendor functions + QEMU behaviour suite | **4.8 %** byte identity; **17/17** behavioural checks pass |
| `buildroot/` | Buildroot 2022.02.3 study, harness and results | BusyBox **99.9899 %** (81 B), zlib **99.9238 %** (73 B) |

## ESP bootloader (verified 100 %)

```sh
cd tools/rebuild/esp-boot
./build.sh                     # default console = UART1 GPIO18/19
./verify.sh                    # rebuilds and asserts the SHA-256
```

The four keys that close the gap are in `patches/sdkconfig.bootloader.fragment`:

```ini
CONFIG_ESP_CONSOLE_UART_CUSTOM=y
CONFIG_ESP_CONSOLE_UART_CUSTOM_NUM_1=y
CONFIG_ESP_CONSOLE_UART_TX_GPIO=18
CONFIG_ESP_CONSOLE_UART_RX_GPIO=19
```

`build.sh` needs Docker and the `espressif/idf:v5.0` image. It writes to
`work/` and `out/`, both ignored by git.

## ESP application

```sh
# upstream-only reference build
cd tools/rebuild/esp-app
./build.sh                     # fetches esp-hosted + protobuf-c, builds the app
./diff.sh                      # positional comparison against the vendor image

# clean-room reconstruction with the vendor modules
cd tools/rebuild/esp-app/recon
./build.sh
python3 tests/qemu_test.py     # 17 behavioural checks under ESP32 QEMU
```

The 65.92 % figure from the upstream-only build is not the vendor application:
it reproduces upstream object files at their original offsets. Replacing the
vendor translation units changes object sizes and shifts the link, so the honest
byte figure for the reconstruction is **4.8 %**. What is exact is the code
coverage: all **204/204** vendor functions are decompiled, and the reconstruction
passes **17/17** behavioural checks.

`recon/` contains `REPORT.md`, `src/` (the reconstructed modules), `tests/`,
`out/functions.csv` (4,601 functions), `module_map.md`, `coverage.json` and
`vtables.json`.

**Note:** the header comment in `esp-app/build.sh` still says the bootloader
reaches ~91.8 %. That figure is stale — the bootloader is now 100 % (see
`esp-boot/`). The application percentages are unaffected.

## Buildroot / BusyBox

`buildroot/configs/e64_vendor_inferred_defconfig` is reconstructed from the
shipped image (Cortex-A7, VFPV4-D16, EABIhf, `-O3`, PIE, `_FORTIFY_SOURCE=2`),
not recovered from the vendor. It is a starting hypothesis.

`buildroot/build.sh` builds an armhf toolchain (variant C), BusyBox 1.35.0 and
zlib 1.2.12, then compares them with the vendor binaries. Current result:

| Package | Size | Same-offset | Residual |
|---|---:|---:|---|
| BusyBox | 801,960 B | **99.9899 %** | 81 B, all CRT/libgcc |
| zlib | 95,772 B | **99.9238 %** | 73 B, all CRT/libgcc |

Every section except `.text` is byte-identical for both. The residual is
instruction scheduling in the vendor's GCC 10.3.0/libgcc, not package code.
`buildroot/results/` holds the comparison JSON, section CSVs, flag matrix,
configs and logs. `scripts/` keeps the individual helpers.

## Caveats

- Scripts were written to run from their original `/tmp` directories. They use
  `HERE`/`ROOT` so a copied tree works, but any hard-coded `/tmp/...` input in
  the Buildroot helpers must be repointed at `.tools/firmware-1.16-24/`.
- Vendor sources for the HSG application, the ESP application and the EKX
  binaries are absent. Those components are documented, not rebuilt.
- These harnesses build and compare only. They do not flash a device.
