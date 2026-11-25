"""Command line entry point for the equivalence harness.

    python3 -m harness.run contract
    python3 -m harness.run run --target targets/vendor.json --scenario all --repeat 2
    python3 -m harness.run determinism --target vendor
    python3 -m harness.run compare --baseline runs/vendor --candidate runs/recon
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import compare as compare_mod
from . import normalise, target as target_mod
from .contract import load_contract, contract_table
from .coverage import coverage as coverage_mod, load_scenarios, render as render_coverage
from .runner import run_scenario

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = ROOT / "scenarios"
RUNS = ROOT / "runs"
RULES = ROOT / "normalisers" / "rules.json"
CLASSIFICATION = ROOT / "diffs" / "classification.json"


def scenario_files(selector: str) -> list[Path]:
    files = sorted(SCENARIO_DIR.glob("*.json"))
    if selector in ("all", "*"):
        return files
    wanted = selector.split(",")
    chosen = [f for f in files if f.stem in wanted or f.stem.startswith(tuple(wanted))]
    if not chosen:
        sys.exit(f"no scenario matched {selector!r} in {SCENARIO_DIR}")
    return chosen


def load_json(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def ensure_profile(target, scenario: dict, state_file: Path, verbose: bool) -> None:
    wanted = scenario.get("profile", "shipped")
    spec = target.spec
    profiles = spec.get("profiles", {})
    current = state_file.read_text().strip() if state_file.exists() else None
    if current == wanted or wanted not in profiles:
        return
    cmd = profiles[wanted].get("cmd")
    if not cmd:
        return
    if verbose:
        print(f"  switching profile to {wanted!r}")
    result = target.shell(cmd, timeout=180)
    if not result.get("ok"):
        sys.exit(f"profile switch failed: {result}")
    target.wait_ready(180)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(wanted)


def cmd_run(args) -> int:
    spec_path = Path(args.target)
    target = target_mod.load(spec_path)
    spec = target.spec
    rules = normalise.load_rules(RULES)
    out_root = Path(args.out) if args.out else RUNS / target.name
    state_file = out_root / ".profile"
    summaries = []

    if args.reset_first and (spec.get("reset_cmd") or spec.get("reset")):
        if spec.get("reset"):
            target.reset()
        else:
            target.shell(spec["reset_cmd"], timeout=240)

    for path in scenario_files(args.scenario):
        scenario = json.loads(path.read_text())
        out_dir = out_root / scenario["id"]
        out_dir.mkdir(parents=True, exist_ok=True)
        ensure_profile(target, scenario, state_file, args.verbose)
        reset_hook = spec.get("reset_cmd")
        has_reset = bool(reset_hook or spec.get("reset"))
        repeat = int(args.repeat or scenario.get("repeat", 1))
        if scenario.get("deterministic", True) is False and args.repeat:
            repeat = 1
        for index in range(1, repeat + 1):
            if scenario.get("reset") == "pristine" and has_reset:
                if args.verbose:
                    print("  resetting to pristine state")
                if spec.get("reset"):
                    result = target.reset()
                else:
                    result = target.shell(reset_hook, timeout=240)
                if not result.get("ok"):
                    print(f"  reset failed: {result}", file=sys.stderr)
                target.wait_ready(240)
            print(f"[{target.name}] {scenario['id']} run {index}/{repeat}")
            summary = run_scenario(target, scenario, out_dir, run_index=index,
                                   verbose=args.verbose)
            raw = Path(summary["raw"])
            norm_path = raw.with_suffix("").with_suffix(".norm.jsonl")
            counts = normalise.write_normalised(raw, norm_path, rules)
            meta = {"scenario": scenario["id"], "run": index,
                    "target": target.name, "raw": str(raw),
                    "normalised": str(norm_path),
                    "elapsed_ms": summary["elapsed_ms"],
                    "records": summary["records"],
                    "normalisation_counts": counts,
                    "profile": scenario.get("profile", "shipped"),
                    "finished_epoch": int(time.time())}
            (out_dir / f"run-{index}.meta.json").write_text(json.dumps(meta, indent=2))
            summaries.append(meta)
            print(f"  {summary['records']} records in {summary['elapsed_ms']} ms")

    if args.repeat and int(args.repeat) > 1:
        for path in scenario_files(args.scenario):
            scenario = json.loads(path.read_text())
            if scenario.get("deterministic", True) is False:
                print(f"determinism {scenario['id']}: SKIPPED (declared non-deterministic)")
                continue
            out_dir = out_root / scenario["id"]
            first = out_dir / "run-1.norm.jsonl"
            result = {"scenario": scenario["id"]}
            diffs = []
            for index in range(2, int(args.repeat) + 1):
                other = out_dir / f"run-{index}.norm.jsonl"
                diffs.append(compare_mod.compare(first, other, scenario["id"], []))
            result["runs"] = int(args.repeat)
            result["identical"] = all(d["identical"] for d in diffs)
            result["comparisons"] = diffs
            (out_dir / "determinism.json").write_text(json.dumps(result, indent=2))
            print(f"determinism {scenario['id']}: "
                  f"{'IDENTICAL' if result['identical'] else 'DIFFERS'}")
            if not result["identical"]:
                for diff in diffs:
                    print(compare_mod.summarise(diff))
    target.close()
    return 0


def _scenario_dirs(root: Path) -> list[Path]:
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "run-1.norm.jsonl").exists())


def _scenario_spec(scenario_id: str) -> dict:
    """Scenario file for a run directory, used for scenario-level flags."""
    path = SCENARIO_DIR / f"{scenario_id}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def cmd_determinism(args) -> int:
    root = RUNS / args.target
    rules = normalise.load_rules(RULES)
    ok_all = True
    results = []
    for directory in _scenario_dirs(root):
        first = directory / "run-1.norm.jsonl"
        others = sorted(directory.glob("run-*.norm.jsonl"))
        if len(others) < 2:
            continue
        com = compare_mod.compare(first, others[1], directory.name, [])
        results.append({"scenario": directory.name, "identical": com["identical"],
                        "mismatches": com["mismatches"], "diff": com})
        print(compare_mod.summarise(com))
        ok_all = ok_all and com["identical"]
    (root / "determinism.json").write_text(json.dumps(
        {"target": args.target, "identical": ok_all,
         "scenarios": [{k: v for k, v in r.items() if k != "diff"} for r in results],
         "details": results}, indent=2))
    print(f"\nbaseline determinism: {'PASS' if ok_all else 'FAIL'}")
    return 0 if ok_all else 1


def cmd_compare(args) -> int:
    baseline = RUNS / args.baseline
    candidate = RUNS / args.candidate
    rules = normalise.load_rules(CLASSIFICATION)
    if isinstance(rules, dict):
        rules = rules.get("rules", [])
    report = {"baseline": args.baseline, "candidate": args.candidate,
              "scenarios": [], "behaviourally_identical": True}
    for directory in _scenario_dirs(baseline):
        spec = _scenario_spec(directory.name)
        other = candidate / directory.name
        if not (other / "run-1.norm.jsonl").exists():
            report["scenarios"].append({"scenario": directory.name,
                                        "status": "missing-candidate"})
            report["behaviourally_identical"] = False
            print(f"{directory.name}: MISSING in candidate")
            continue
        com = compare_mod.compare(directory / "run-1.norm.jsonl",
                                  other / "run-1.norm.jsonl",
                                  directory.name, rules,
                                  until_step=spec.get("compare_until"))
        report["scenarios"].append({
            "scenario": directory.name,
            "behaviourally_identical": com["behaviourally_identical"],
            "mismatches": com["mismatches"],
            "expected": com["expected"],
            "compared_until": com.get("compared_until"),
            "records_not_compared": {
                "vendor": com.get("records_dropped_a", 0),
                "candidate": com.get("records_dropped_b", 0),
            },
        })
        report["behaviourally_identical"] &= com["behaviourally_identical"]
        print(compare_mod.summarise(com))
    out = RUNS / f"compare-{args.baseline}-vs-{args.candidate}.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\nverdict: {'BEHAVIOURALLY IDENTICAL' if report['behaviourally_identical'] else 'MISMATCH'}"
          f"  -> {out}")
    return 0 if report["behaviourally_identical"] else 1


def cmd_contract(args) -> int:
    contract = load_contract(ROOT / "contract" / "hmi_contract.json")
    if args.json:
        print(json.dumps(contract, indent=2))
        return 0
    print(contract_table(contract, surfaces=args.surface.split(",") if args.surface else None))
    return 0


def cmd_coverage(args) -> int:
    contract = load_contract(ROOT / "contract" / "hmi_contract.json")
    scenarios = load_scenarios(SCENARIO_DIR)
    result = coverage_mod(contract, scenarios)
    print(render_coverage(result))
    if args.json:
        print(json.dumps(result, indent=2))
    return 0 if not args.strict or result["covered"] == result["total"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="equiv")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="execute scenarios against a target")
    p_run.add_argument("--target", required=True, help="target spec JSON")
    p_run.add_argument("--scenario", default="all")
    p_run.add_argument("--repeat", type=int, default=0)
    p_run.add_argument("--out", default=None)
    p_run.add_argument("--reset-first", action="store_true")
    p_run.add_argument("--verbose", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_det = sub.add_parser("determinism", help="compare repeated runs of one target")
    p_det.add_argument("--target", required=True)
    p_det.set_defaults(func=cmd_determinism)

    p_cmp = sub.add_parser("compare", help="compare two target run trees")
    p_cmp.add_argument("--baseline", required=True)
    p_cmp.add_argument("--candidate", required=True)
    p_cmp.set_defaults(func=cmd_compare)

    p_con = sub.add_parser("contract", help="print the observable contract")
    p_con.add_argument("--json", action="store_true")
    p_con.add_argument("--surface", default=None)
    p_con.set_defaults(func=cmd_contract)

    p_cov = sub.add_parser("coverage", help="report which contract rows the suite exercises")
    p_cov.add_argument("--json", action="store_true")
    p_cov.add_argument("--strict", action="store_true",
                       help="exit non-zero unless every row is covered")
    p_cov.set_defaults(func=cmd_coverage)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
