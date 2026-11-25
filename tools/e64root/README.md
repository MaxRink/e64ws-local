# e64root

One-click owner root and SSH for an E64 WS / NG2 grinder, using the two runtime
paths verified in this repository:

- **FW-01** — `login.php` login-form command injection.
- **FW-02** — unauthenticated `upload_esp.php` archive execution.

Full guide, preconditions, risk and evidence: [docs/ROOT_TOOL.md](../../docs/ROOT_TOOL.md).

## Commands

```sh
tools/e64root/e64root probe  --host 192.168.1.50
tools/e64root/e64root web    --host 192.168.1.50 --dry-run
tools/e64root/e64root web    --host 192.168.1.50 --yes
tools/e64root/e64root ssh    --host 192.168.1.50 --key ~/.ssh/id_ed25519.pub --yes
tools/e64root/e64root verify --host 192.168.1.50
tools/e64root/e64root revert --host 192.168.1.50 --dry-run
```

`python3 -m e64root` and `python3 -m tools.e64root` work when `tools/` is on
`sys.path`.

## Safety model

- No change without `--yes`; `--dry-run` contacts nothing.
- Private/loopback/link-local targets only unless `--allow-public`.
- TLS verification on by default; the vendor certificate is self-signed, so
  `--insecure` or `--ca-file` is required for actions.
- No binary downloads, vendor keys, SWUs or cloud credentials.
- Revert removes only e64root-identified files and restores backups.

## Tests

```sh
cd tools
python3 -m unittest discover -s e64root/tests -t .
```

121 tests, 1 skipped (the opt-in virtual-grinder fingerprint test).

## Scope

Only for a grinder you own or are authorized to service. The CLI has been
exercised offline against fixtures and loopback servers; it has **not** been run
against physical hardware in this repository. `/log` writability is the
load-bearing unknown for FW-02, so FW-01 is the recommended first path.
