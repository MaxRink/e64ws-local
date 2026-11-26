# E64 WS local research — public code snapshot

Interoperability code for the **Mahlkönig / Hemro E64 WS** espresso grinder and its
"Grind by Sync" software: Android and iOS clients, the on-device PHP modules those
clients install, a local-cloud compose skeleton, reverse-engineering and
reimplementation tooling, and the test suites that go with them.

This is a **curated source snapshot**. It is not a mirror of the private research
tree it was assembled from, it carries no history, and it deliberately excludes the
vendor material that research was based on. Nothing here is endorsed, reviewed or
supported by the vendor.

## What is here

| Area | What it is |
|---|---|
| `apps/android/` | Kotlin/Compose client, unit and instrumented tests |
| `apps/ios/` | Foundation-only Swift core with a generated test matrix |
| `ondevice/` | PHP modules served by the grinder's web UI |
| `deploy/local-cloud/` | compose skeleton, Caddy configs, dev-cert script |
| `tools/` | protocol clients, simulators, parsers, rebuild scripts, a local-cloud service and its suites |
| `tests/` | root client, BLE, bridge and fixture suites |
| `docker/`, `integrations/` | dev-environment image, adapter for the separate `decaid` tool |
| `.github/` | issue forms, dependabot, and the research tree's workflow definitions |

## What is deliberately absent, and why

Everything below was withheld on purpose. The reasons are legal and risk
judgements, not accidents of export.

| Absent | Why |
|---|---|
| **Vendor firmware** — the eight `.swu` release containers (~507 MiB), their LFS store, and the hash manifest that describes them | Vendor copyright. Nothing in the research tree records a redistribution grant, and "publicly downloadable" is not "redistributable". |
| **Vendor documentation** — manual pages, help text, and screenshots of either | Vendor copyright. |
| **Decompiled and reconstructed vendor material** — decompiler output, function/field/string ledgers, reconstructed sources, recovered QML resources, differential reports | Derivative of vendor binaries, with no established right to publish. That is a lawyer's call, so none of it ships. |
| **Credentials and key material** — a vendor GitLab token, a root password verifier, SSH authorised keys, certificate inventories, capture files | Never publishable, here or anywhere else. |
| **Recorded evidence** — device and VM output, service responses, wire captures, HMI screenshots | Contains vendor responses and, in places, machine and network identifiers. |
| **Our own research prose** — analysis documents, advisories, internal handover notes | It asserts uncoordinated security findings about a named vendor's product. Disclosure timing is not ours to publish unilaterally. |
| **Fixtures recorded on the owner's grinder** | Withheld until their sanitisation has been re-read. |
| **Nested third-party checkouts, machine-local trees, build outputs** | Either not ours to redistribute, or reproducible from the build scripts that are here. |

Consequences you will notice: paths the code refers to (`firmware/`, `docs/`,
`captures/`, `decaid/`) do not exist in this repository, and tooling and tests that
read them cannot run here.

## Security posture

- **No history.** The repository has a single commit. The private tree's history
  carries credential material from its root commit onwards, so a bundle, mirror,
  fork or force-push of history would republish it regardless of what any tip
  looks like. A contents-only snapshot is the only safe transport, and that is what
  this is.
- **Selection, then independent verification.** Paths were selected by an
  allow-list, narrowed by a withhold-list, and then passed through a deny-list that
  fails on GitLab access tokens, private-key markers, crypt(3) password verifiers,
  Git LFS pointers, and any path under `firmware/`, `.tools/`, `captures/`, `dist/`,
  `decaid/`, `docs/bible/`, `docs/LEGAL/` or `docs/evidence/`. The patterns are
  not reproduced here for the obvious reason. The exported tree was
  then re-scanned by a second, independent implementation before the first push:
  **0 findings across 460 files, 4,755,814 bytes**, largest file 169,274 B. This
  README and `SECURITY.md` are the only files the exporter did not produce.
- **No binaries and no keys.** No firmware images, no compiled vendor artefacts, no
  private keys or password hashes, no LFS objects, no submodules.
- **Workflows are included; Actions is off.** The three workflow definitions are the
  research tree's. Two of them assert against material that is not published, so
  Actions is disabled for this snapshot instead of being left permanently red.
  Re-enable it once you have adapted them.
- **Vulnerabilities.** See [`SECURITY.md`](SECURITY.md): private reporting only, and
  vendor binaries and credential material are explicitly out of scope for
  contributions — a pull request that adds them is rejected.
- **No licence.** None has been chosen yet, so default copyright applies: you can
  read and fork on GitHub, but no other rights are granted. Nothing here grants any
  right to vendor material, because none is included.

## Running what runs here

```sh
python3 -m unittest discover -s tests -q
```

That root suite is self-contained and passes in a clean clone. `tools/run_tests.py`
runs what this repository carries and says plainly what it does not:

- a suite whose input is withheld declares it in `requires` and reports `SKIP`
  naming the missing path — the deep C++ recon suite (reconstructed vendor
  sources), the boot-script rehearsal (a built `boot.scr`) and the equivalence
  self-test (a recorded vendor capture baseline);
- a module this repository does not carry, or whose data is withheld, is declared
  with the input that makes its absence legitimate; its declared share comes off
  the suite floor and it is listed as not run with that path, so the modules that
  are present still have to clear their own share;
- a test that reads a withheld document skips with the same reason, through
  `tools/required_inputs.py`, which is the one place that decides what is missing
  and how it is said.

None of that weakens a check where the input exists: the research tree runs the
same code and every assertion, 13 suites and 1041 tests. Here the table tells you
which is which.

## Nothing here is vendor-endorsed

This is independent interoperability research. It is **not** endorsed, sponsored,
reviewed, approved or supported by Mahlkönig, Hemro, or any of their subsidiaries,
distributors or partners, and it was not commissioned by them. The vendor has not
seen this code.

"Mahlkönig", "Hemro", "E64 WS" and "Grind by Sync" are trademarks of their
respective owners. They are used here only to name the product this code
interoperates with.

Use it on hardware you own, and understand that installing anything on a device may
void its warranty or its support arrangements.

## Provenance

The tree was produced from the private research repository at commit `b369505` by an
allow-list exporter: every file except this README and `SECURITY.md` is a verbatim
copy of a tracked blob from that commit. The policy the exporter enforces, including
the list of what it refuses and why, is deliberately not part of this repository —
its deny-list contains the very literals it scans for.
