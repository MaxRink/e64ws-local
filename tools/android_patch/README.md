# Local Android patch pipeline

This directory contains a local-only, hash-pinned pipeline for the
owner-supplied Mahlkönig Sync Android split APK set `1.0.11-4640`.

The safe same-length patch replaces all four `sync.mahlkoenig.com` occurrences
in `libapp.so` with the reserved non-resolving host `cloud-block.invalid`.
Local onboarding route literals are verified unchanged.

The account gate does **not** yet have an evidence-supported Dart-AOT
instruction patch. The normal pipeline therefore fails closed unless supplied
with a high-confidence gate patch matching `gate_patch.schema.json`. The
`--allow-cloud-only-diagnostic` mode exists only to test repacking and local
development signing; it does not produce an account-free app.

See `docs/ANDROID_LOCAL_PATCH.md` for commands, evidence, schemas, and the exact
blocker.
