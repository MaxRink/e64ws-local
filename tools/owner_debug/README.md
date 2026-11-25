# Owner-firmware audit helper

`inspect_owner_firmware.py` is a read-only, offline evidence checker for the
extracted E64 WS firmware tree. It verifies the supplied manifest/payload
hashes, SWUpdate signature boundary, static SSH/serial evidence, U-Boot
capability strings, and selected update/ESP/eFuse source markers.

```sh
python3 tools/owner_debug/inspect_owner_firmware.py
```

The default mode prints JSON and does not open device nodes, connect to the
network, flash anything, enable SSH, or modify firmware. A live grinder is
required to establish reachability, runtime execution, eFuse state, U-Boot
environment, watchdog behavior, or an actual login/listener. The helper also
intentionally does not attempt a shell or exploit path.
