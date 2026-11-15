#!/usr/bin/env python3
"""Compare two validated CrossState snapshots by bucket and logical record."""

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


def _bucket_index(records):
    """Group records by bucket (slot) -> list of records."""
    buckets: dict[int, list[dict]] = {}
    for rec in records:
        buckets.setdefault(rec["slot"], []).append(rec)
    return buckets


def _records_by_key(bucket_records):
    """Within a bucket, index records by key tuple."""
    return {tuple(r["key"]): r for r in bucket_records}


def compare_snapshots(left, right):
    left_buckets = _bucket_index(left["records"])
    right_buckets = _bucket_index(right["records"])

    left_slots = set(left_buckets)
    right_slots = set(right_buckets)

    exact_matches = []
    differing_records = []
    bucket_conflicts = []
    bucket_chain_overflow = []

    # Buckets present on both sides: compare records by key within each bucket.
    for slot in sorted(left_slots & right_slots):
        left_by_key = _records_by_key(left_buckets[slot])
        right_by_key = _records_by_key(right_buckets[slot])

        left_keys = set(left_by_key)
        right_keys = set(right_by_key)

        # Same bucket, different key sets -> conflict (chain overflow or split).
        if left_keys != right_keys:
            bucket_conflicts.append({
                "slot": slot,
                "left_keys": sorted(left_keys - right_keys),
                "right_keys": sorted(right_keys - left_keys),
                "left_count": len(left_buckets[slot]),
                "right_count": len(right_buckets[slot]),
            })
            continue

        # Same keys in the bucket: compare logical fields.
        for key in sorted(left_keys):
            a = left_by_key[key]
            b = right_by_key[key]

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
                    "key": list(key),
                    "chain_index": a.get("chain_index", 0),
                    "differences": differences,
                })
            else:
                exact_matches.append(slot)

    return {
        "format": "crossstate-snapshot-comparison",
        "version": 2,
        "left_target": left["source_target"],
        "right_target": right["source_target"],
        "left_buckets": len(left_buckets),
        "right_buckets": len(right_buckets),
        "left_records": len(left["records"]),
        "right_records": len(right["records"]),
        "exact_matches": exact_matches,
        "differing_records": differing_records,
        "bucket_conflicts": bucket_conflicts,
        "bucket_chain_overflow": bucket_chain_overflow,
        "left_only_slots": sorted(left_slots - right_slots),
        "right_only_slots": sorted(right_slots - left_slots),
        "equivalent": (
            left_slots == right_slots
            and not differing_records
            and not bucket_conflicts
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
    print(f"Left: {report['left_target']} ({report['left_buckets']} buckets, {report['left_records']} records)")
    print(f"Right: {report['right_target']} ({report['right_buckets']} buckets, {report['right_records']} records)")
    print(f"Exact matches: {len(report['exact_matches'])}")
    print(f"Same-bucket records with different values: {len(report['differing_records'])}")
    print(f"Bucket key conflicts: {len(report['bucket_conflicts'])}")
    print(f"Left-only buckets: {len(report['left_only_slots'])}")
    print(f"Right-only buckets: {len(report['right_only_slots'])}")
    print(f"Report: {output}")
    print("Equivalent:", report["equivalent"])
    print("SNAPSHOT_COMPARISON = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
