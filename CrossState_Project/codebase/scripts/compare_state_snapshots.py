#!/usr/bin/env python3
"""Compare two validated CrossState snapshots by slot and logical record."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.state_snapshot import validate_snapshot

RECORD_FIELDS = ("st", "last", "pkts", "bytes")


def load_snapshot(path):
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_snapshot(snapshot)
    if errors:
        raise ValueError(
            f"Invalid snapshot {path}:\n- " + "\n- ".join(errors)
        )
    return snapshot


def compare_snapshots(left, right):
    left_by_slot = {record["slot"]: record for record in left["records"]}
    right_by_slot = {record["slot"]: record for record in right["records"]}

    left_slots = set(left_by_slot)
    right_slots = set(right_by_slot)

    exact_matches = []
    differing_records = []
    slot_conflicts = []

    for slot in sorted(left_slots & right_slots):
        a = left_by_slot[slot]
        b = right_by_slot[slot]

        if a["key"] != b["key"]:
            slot_conflicts.append({
                "slot": slot,
                "left_key": a["key"],
                "right_key": b["key"],
            })
            continue

        differences = {
            field: {
                "left": a[field],
                "right": b[field],
            }
            for field in RECORD_FIELDS
            if a[field] != b[field]
        }

        if differences:
            differing_records.append({
                "slot": slot,
                "key": a["key"],
                "differences": differences,
            })
        else:
            exact_matches.append(slot)

    return {
        "format": "crossstate-snapshot-comparison",
        "version": 1,
        "left_target": left["source_target"],
        "right_target": right["source_target"],
        "left_records": len(left_by_slot),
        "right_records": len(right_by_slot),
        "exact_matches": exact_matches,
        "differing_records": differing_records,
        "slot_conflicts": slot_conflicts,
        "left_only_slots": sorted(left_slots - right_slots),
        "right_only_slots": sorted(right_slots - left_slots),
        "equivalent": (
            left_slots == right_slots
            and not differing_records
            and not slot_conflicts
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "left",
        nargs="?",
        type=Path,
        default=ROOT / "artifacts/state/bmv2_snapshot.json",
    )
    parser.add_argument(
        "right",
        nargs="?",
        type=Path,
        default=ROOT / "artifacts/state/xdp_snapshot.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts/state/snapshot_comparison.json",
    )
    args = parser.parse_args()

    try:
        report = compare_snapshots(
            load_snapshot(args.left),
            load_snapshot(args.right),
        )

        output = args.output
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        print(f"SNAPSHOT_COMPARISON = FAIL\n{exc}", file=sys.stderr)
        return 1

    print("========== SNAPSHOT COMPARISON ==========")
    print(f"Left: {report['left_target']} ({report['left_records']} records)")
    print(f"Right: {report['right_target']} ({report['right_records']} records)")
    print(f"Exact matches: {len(report['exact_matches'])}")
    print(f"Same-slot records with different values: {len(report['differing_records'])}")
    print(f"Same-slot conflicting keys: {len(report['slot_conflicts'])}")
    print(f"Left-only slots: {len(report['left_only_slots'])}")
    print(f"Right-only slots: {len(report['right_only_slots'])}")
    print(f"Report: {output}")
    print("Equivalent:", report["equivalent"])
    print("SNAPSHOT_COMPARISON = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
