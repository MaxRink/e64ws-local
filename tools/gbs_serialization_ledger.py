#!/usr/bin/env python3
"""Generate the native GBS/recipe JSON evidence ledger.

This is a checked-in, evidence-index generator rather than a binary parser.
The field rows are transcribed from the instruction-cross-checked serializer
analysis for the named firmware build. Keeping them in one machine-readable
table makes stale host schemas easier to detect without pretending that a
deployed SQLite BLOB sample is available.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROWS = [
    # Native algorithm serializers.
    ("algorithm", "GbS1", "0x003277dc", "type", "top-level", "string", "no", '"GbS1"', "discriminator"),
    ("algorithm", "GbS1", "0x003277dc", "version", "top-level", "integer", "no", "1", "schema version"),
    ("algorithm", "GbS1", "0x003277dc", "history", "top-level", "array<number>", "no", "", "numeric history values"),
    ("algorithm", "GbS1", "0x003277dc", "lastBrewDurationInSec", "top-level", "number|null", "no", "", "null when source duration is NaN"),
    ("algorithm", "GbS1", "0x003277dc", "coarsenessInMicroMeter", "top-level", "number|null", "no", "", "null when source value is NaN"),
    ("algorithm", "GbS1", "0x003277dc", "quantizedCoarseness", "top-level", "number|null", "no", "", "null when source value is NaN"),
    ("algorithm", "GbS2", "0x00329f2c", "type", "top-level", "string", "no", '"GbS2"', "discriminator"),
    ("algorithm", "GbS2", "0x00329f2c", "version", "top-level", "integer", "no", "1", "schema version"),
    ("algorithm", "GbS2", "0x00329f2c", "history", "top-level", "array<object>", "no", "", "bounded sample history"),
    ("algorithm", "GbS2", "0x00329f2c", "effectiveGrindSizeUm", "history[]", "number", "no", "", "sample x coordinate"),
    ("algorithm", "GbS2", "0x00329f2c", "brewDurationSec", "history[]", "number", "no", "", "sample y coordinate"),
    ("algorithm", "GbS3", "0x0032c4e8", "type", "top-level", "string", "no", '"GbS3"', "discriminator"),
    ("algorithm", "GbS3", "0x0032c4e8", "version", "top-level", "integer", "no", "2", "schema version"),
    ("algorithm", "GbS3", "0x0032c4e8", "history", "top-level", "array<object>", "no", "", "bounded sample history"),
    ("algorithm", "GbS3", "0x0032c4e8", "effectiveGrindSizeUm", "history[]", "number", "no", "", "sample x coordinate"),
    ("algorithm", "GbS3", "0x0032c4e8", "brewDurationSec", "history[]", "number", "no", "", "sample y coordinate"),
    ("algorithm", "GbS3", "0x0032c4e8", "filteredDdTimesBrew", "top-level", "number", "yes", "", "optional engagement flag"),
    ("algorithm", "GbS3", "0x0032c4e8", "farFactor", "top-level", "number", "no", "", "factor"),
    ("algorithm", "GbS3", "0x0032c4e8", "midFactor", "top-level", "number", "no", "", "factor"),
    ("algorithm", "GbS3", "0x0032c4e8", "nearFactor", "top-level", "number", "no", "", "factor"),
    ("algorithm", "GbS3", "0x0032c4e8", "ddTimesBrewFilter", "top-level", "number", "no", "", "filter retention"),
    ("algorithm", "GbS3", "0x0032c4e8", "nearPhaseHoldCyclesSetting", "top-level", "integer", "no", "", "hold setting"),
    ("algorithm", "GbS3", "0x0032c4e8", "nearPhaseHoldCyclesRemaining", "top-level", "integer", "no", "", "hold countdown"),
    ("algorithm", "GbS3", "0x0032c4e8", "lastAdjustmentInDeciMicroMeters", "top-level", "integer", "yes", "", "optional engagement flag"),
    ("algorithm", "GbS3", "0x0032c4e8", "lastTargetDdInDeciMicroMeters", "top-level", "integer", "yes", "", "optional engagement flag"),
    ("algorithm", "GbS3", "0x0032c4e8", "thresBrewDurationErrorNearSec", "top-level", "number", "no", "", "near threshold"),
    ("algorithm", "GbS3", "0x0032c4e8", "keepMediumIntervalWidth", "top-level", "boolean", "no", "", "medium policy"),
    ("algorithm", "GbS4", "0x00333b7c", "type", "top-level", "string", "no", '"GbS4"', "discriminator"),
    ("algorithm", "GbS4", "0x00333b7c", "version", "top-level", "integer", "no", "2", "schema version"),
    ("algorithm", "GbS4", "0x00333b7c", "history", "top-level", "array<object>", "no", "", "bounded sample history"),
    ("algorithm", "GbS4", "0x00333b7c", "effectiveGrindSizeUm", "history[]", "number", "no", "", "sample x coordinate"),
    ("algorithm", "GbS4", "0x00333b7c", "brewDurationSec", "history[]", "number", "no", "", "sample y coordinate"),
    ("algorithm", "GbS4", "0x00333b7c", "filteredDdTimesBrew", "top-level", "number", "yes", "", "optional engagement flag"),
    ("algorithm", "GbS4", "0x00333b7c", "nearPhaseHoldCyclesRemaining", "top-level", "integer", "no", "", "hold countdown"),
    ("algorithm", "GbS4", "0x00333b7c", "lastTargetDdInDeciMicroMeters", "top-level", "integer", "yes", "", "optional engagement flag"),
    ("algorithm", "GbS4", "0x00333b7c", "lastAdjustmentInDeciMicroMeters", "top-level", "integer", "yes", "", "optional engagement flag"),
    ("algorithm", "DdEff", "0x00338a80", "type", "top-level", "string", "no", '"DdEff"', "discriminator"),
    ("algorithm", "DdEff", "0x00338a80", "version", "top-level", "integer", "no", "1", "schema version"),
    ("algorithm", "DdEff", "0x00338a80", "initialCoarsenessDum", "top-level", "integer", "no", "", "exact spelling; deci-um"),
    # Adjacent native JSON paths.
    ("recipe", "recipeState", "0x00343f0c", "initializationValueMym", "top-level", "integer", "no", "", "indented QJsonDocument"),
    ("recipe", "recipeState", "0x00343f0c", "coursenessDeciMym", "top-level", "integer", "no", "", "firmware spelling"),
    ("recipe", "recipeState", "0x00343f0c", "gbsMode", "top-level", "enum-string", "no", "", "Qt enum representation"),
    ("debug", "grindDebug", "0x00349adc", "gbsGrindSizeUm", "top-level", "number", "no", "", "Dum converted by 0.1"),
    ("debug", "grindDebug", "0x00349adc", "gbsAlgoInstance", "top-level", "integer", "no", "", "algorithm instance"),
    ("debug", "grindDebug", "0x00349adc", "gbsAlgoData", "top-level", "json-value", "no", "", "existing algorithm-state value"),
    ("predictor", "effectiveDd", "0x003394f0", "version", "top-level", "integer", "no", "1", "compact JSON"),
    ("predictor", "effectiveDd", "0x003394f0", "grindSizeUm", "top-level", "number", "no", "", "compact JSON"),
    ("negative-evidence", "GbS1/GbS2", "rodata", "lastResultInDeciMicroMeter", "adjacent literal", "integer", "n/a", "", "not in recovered normal V1/V2 serializer pairs"),
]


FIELDS = (
    "domain",
    "schema",
    "evidence_address",
    "key",
    "location",
    "json_type",
    "optional",
    "literal_value",
    "notes",
)


def write_outputs(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "gbs_json_fields.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(FIELDS)
        writer.writerows(ROWS)
    summary = {
        "firmware_build": "HEM-HSG-HMI-S01 V01.16-24",
        "field_rows": len(ROWS),
        "algorithm_schemas": ["GbS1", "GbS2", "GbS3", "GbS4", "DdEff"],
        "native_sqlite_row_sample_available": False,
        "grind_debug_persistence_encoding_known": False,
        "generated_by": "tools/gbs_serialization_ledger.py",
    }
    (output_dir / "gbs_json_fields_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("docs/generated/gbs-serialization"),
    )
    args = parser.parse_args()
    write_outputs(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
