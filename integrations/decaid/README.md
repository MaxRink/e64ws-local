# Decaid/E64 WS reference adapter

`e64ws_adapter.py` is a small Python sidecar/reference implementation for the
proposed Decaid integration. It provides:

- normalized read-only grinder snapshots;
- recommendation-only brew-time and sensory guidance;
- reusable decoded dial-in/GBS primitives via `tools/gbs_model.py`;
- a concrete `DecaidCapabilityPolicy` with fresh-snapshot, bounds, rate, and
  redacted audit gates;
- explicit conversion of a **valid, unique, fresh** Decaid mass shot to the
  recovered local `GrinderActionAddBrewEvent` shape only when an owner has
  configured a matching, live-validated wire profile;
- a separately gated `GrinderActionSetAgsaTargetDdValue` call;
- the device's **unlock tier** — `stock`, `dev`, `root`, `root-custom-api` or
  `unknown` — as `tools/unlock_tiers.detect()` decided it from the facts this
  adapter could observe, with the detector's own evidence, reasons and
  `unseparated` neighbour (`unlock_tier.py`, `docs/UNLOCK_TIERS.md` §7).

It is intentionally not an installable Decaid plugin. Decaid's production
implementation should use a native typed grinder capability and host-owned
transport/credential broker as described in
[`docs/DECAID_INTEGRATION_PROPOSALS.md`](../../docs/DECAID_INTEGRATION_PROPOSALS.md).

From the repository root, a local import smoke test is:

```sh
python3 - <<'PY'
from integrations.decaid.e64ws_adapter import E64DecaidAdapter
print(E64DecaidAdapter.recommend(
    target_brew_time_s=28,
    actual_brew_time_s=22,
    flavor="acidic",
))
PY
```

No network request is made by that example. Automatic actuation is disabled
unless the caller explicitly enables it, and it remains unsafe until the
physical DD/dial direction and firmware limits are measured on the target.

The unlock tier is the one call that does make a request, and it makes exactly
one (`POST /rest_api/capabilities`) unless an action probe is authorised:

```python
from integrations.decaid.e64ws_adapter import E64DecaidAdapter
from tools.e64ws_api import E64LocalAPI

adapter = E64DecaidAdapter(E64LocalAPI(host, insecure=True), owner_token=token)
report = adapter.unlock_tier()      # facts in, detect()'s verdict out
report.tier                         # 'dev', or 'unknown' — never a guess
report.unseparated                  # ('root', 'root-custom-api')
report.reasons                      # the detector's own sentences
```

The facts it can and cannot justify, the opt-in `ActionProbe` and its cost, and
one worked example per outcome are in
[`docs/UNLOCK_TIERS.md`](../../docs/UNLOCK_TIERS.md) §7.

For an explicit actuation prototype, construct `DecaidCapabilityPolicy` with
owner-measured `dd_bounds`, `allow_actuation=True`, and a fresh read snapshot;
the adapter still enforces the snapshot, fault, and rate gates. The policy
does not make the native DD value equivalent to a dial number.

Flow-only machine telemetry is intentionally not accepted by
`record_brew_event`. Use `tools.decaid_flow.MachineFlowOnlyEvent` for that
lane; it has no mass/yield and is permanently ineligible for E64 event
injection. OpenScale itself can be used without Decaid through
`python -m tools.openscale_cli` and `tools.openscale_shots`.
