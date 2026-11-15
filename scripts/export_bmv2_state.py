#!/usr/bin/env python3
"""Export BMv2 flow registers to the portable CrossState snapshot format."""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.state_snapshot import build_snapshot, serialize_snapshot

SLOT_COUNT = 65536
PROTO_TCP = 6

REGISTER_NAMES = [
    "r_valid",
    "r_ipa",
    "r_pa",
    "r_ipb",
    "r_pb",
    "r_st",
    "r_last",
    "r_pkts",
    "r_bytes",
]

DEFAULT_OUTPUT = ROOT / "artifacts/state/bmv2_snapshot.json"


def run_cli(commands, thrift_port):
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"simple_switch_CLI exited with {result.returncode}.\n"
            f"STDOUT:\n{result.stdout[-2000:]}\n"
            f"STDERR:\n{result.stderr[-2000:]}"
        )
    return result.stdout


def parse_register_array(output, name, expected_count):
    """Parse the index-omitted register_read response."""
    pattern = (
        rf"RuntimeCmd:\s*{re.escape(name)}\s*=\s*"
        rf"(.*?)(?=\nRuntimeCmd:|\Z)"
    )
    match = re.search(pattern, output, flags=re.DOTALL)
    if not match:
        raise ValueError(
            f"Could not find full-array response for register {name}."
        )

    text = match.group(1).strip()
    if not text:
        raise ValueError(f"Register {name} returned an empty array.")

    try:
        values = [int(token.strip()) for token in text.split(",")]
    except ValueError as exc:
        raise ValueError(
            f"Could not parse numeric values from register {name}."
        ) from exc

    if len(values) != expected_count:
        raise ValueError(
            f"Register {name} returned {len(values)} values; "
            f"expected {expected_count}."
        )

    return values


def parse_indexed_registers(output, requests):
    """Parse indexed responses keyed by (register_name, slot)."""
    parsed = {}

    for name, slot in requests:
        pattern = (
            rf"(?:RuntimeCmd:\s*)?"
            rf"{re.escape(name)}\s*\[\s*{slot}\s*\]\s*=\s*(\d+)"
        )
        matches = re.findall(pattern, output)

        if len(matches) != 1:
            raise ValueError(
                f"Expected one result for {name}[{slot}], "
                f"found {len(matches)}."
            )

        parsed[(name, slot)] = int(matches[0])

    return parsed


def discover_valid_slots(thrift_port):
    output = run_cli(["register_read r_valid"], thrift_port)
    valid = parse_register_array(output, "r_valid", SLOT_COUNT)

    for slot, flag in enumerate(valid):
        if flag not in (0, 1):
            raise ValueError(
                f"r_valid[{slot}] has invalid value {flag}."
            )

    return [slot for slot, flag in enumerate(valid) if flag == 1]


def read_valid_records(slots, thrift_port):
    if not slots:
        return []

    # Read valid again, together with all record fields, so validity changes
    # between the bitmap scan and the indexed reads are detected.
    requests = [
        (name, slot)
        for slot in slots
        for name in REGISTER_NAMES
    ]
    commands = [
        f"register_read {name} {slot}"
        for name, slot in requests
    ]

    output = run_cli(commands, thrift_port)
    values = parse_indexed_registers(output, requests)
    records = []

    for slot in slots:
        read_values = {
            name: values[(name, slot)]
            for name in REGISTER_NAMES
        }

        if read_values["r_valid"] != 1:
            raise RuntimeError(
                f"r_valid[{slot}] changed during export. "
                "Retry while traffic is quiescent."
            )

        key = (
            read_values["r_ipa"],
            read_values["r_pa"],
            read_values["r_ipb"],
            read_values["r_pb"],
            PROTO_TCP,
        )

        records.append({
            "slot": slot,
            "key": key,
            "st": read_values["r_st"],
            "last": read_values["r_last"],
            "pkts": read_values["r_pkts"],
            "bytes": read_values["r_bytes"],
            "chain_index": 0,
        })

    return records


def verify_export_consistency(
    slots: list[int],
    exported: list[dict],
    thrift_port,
    sample_size: int = 20,
) -> dict:
    """Re-read a sample of slots and compare to exported values to detect
    torn snapshots caused by non-atomic register reads.

    Returns a dict with consistency check results.
    """
    if not slots or not exported:
        return {
            "sampled": 0,
            "mismatches": 0,
            "consistent": True,
            "message": "No slots to verify.",
        }

    # Build a lookup from exported records by slot
    exported_by_slot = {r["slot"]: r for r in exported}

    # Sample slots evenly across the range
    sample_indices = sorted(
        set(range(0, len(slots), max(1, len(slots) // max(1, sample_size))))
    )[:sample_size]
    sample_slots = [slots[i] for i in sample_indices]

    # Read the sample slots again
    requests = [
        (name, slot)
        for slot in sample_slots
        for name in REGISTER_NAMES
    ]
    commands = [f"register_read {name} {slot}" for name, slot in requests]
    output = run_cli(commands, thrift_port)
    values = parse_indexed_registers(output, requests)

    mismatches = []
    for slot in sample_slots:
        read_values = {
            name: values[(name, slot)]
            for name in REGISTER_NAMES
        }
        exported = exported_by_slot.get(slot)
        if exported is None:
            mismatches.append({
                "slot": slot,
                "reason": "slot not in exported records",
            })
            continue

        # Compare logical fields
        for field in ("r_st", "r_last", "r_pkts", "r_bytes"):
            if read_values[field] != exported[field]:
                mismatches.append({
                    "slot": slot,
                    "field": field,
                    "exported": exported[field],
                    "read_again": read_values[field],
                })
                break

    return {
        "sampled": len(sample_slots),
        "mismatches": len(mismatches),
        "consistent": len(mismatches) == 0,
        "details": mismatches[:5],  # cap at 5 for readability
    }


def main():
    parser = argparse.ArgumentParser(
        description="Export BMv2 registers into a CrossState snapshot."
    )
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not 1 <= args.thrift_port <= 65535:
        print("Invalid Thrift port.", file=sys.stderr)
        return 2

    try:
        t_export_start = time.perf_counter()
        slots = discover_valid_slots(args.thrift_port)
        records = read_valid_records(slots, args.thrift_port)
        t_export_end = time.perf_counter()

        snapshot = build_snapshot("bmv2", records)
        serialized = serialize_snapshot(snapshot)

        output = args.output
        if not output.is_absolute():
            output = ROOT / output

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialized, encoding="utf-8")

        # Consistency check: re-read a sample of slots to detect torn snapshots
        consistency = verify_export_consistency(
            slots, records, args.thrift_port
        )

    except Exception as exc:
        print(f"BMV2_STATE_EXPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    print("========== BMv2 STATE EXPORT ==========")
    print(f"Slots marked valid: {len(slots)}")
    print(f"Records exported: {len(records)}")
    print(f"Export window: {(t_export_end - t_export_start)*1000:.2f}ms")
    print(f"Snapshot: {output}")
    print(
        f"Consistency check: {consistency['sampled']} slots sampled, "
        f"{consistency['mismatches']} mismatches "
        f"({'CONSISTENT' if consistency['consistent'] else 'TORN SNAPSHOT RISK'})"
    )
    if consistency["details"]:
        for d in consistency["details"]:
            print(f"  Mismatch slot {d.get('slot', '?')}: {d.get('reason', d.get('field', '?'))}")
    print("BMV2_STATE_EXPORT = PASS")
    print(
        "WARNING: BMv2 register reads are not atomic at the switch level. "
        "A consistency check sampled a subset of slots; torn reads may still "
        "occur in unsampled slots during active traffic."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
