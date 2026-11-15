#!/usr/bin/env python3
"""Validated, dry-run-first import of CrossState snapshots into XDP."""

import argparse
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import key_bytes, slot_of
from scripts.export_xdp_state import (
    decode_bytes,
    decode_record_value,
    parse_integer,
)
from scripts.state_snapshot import validate_snapshot

RECORD_BYTES = 40
KEY_BYTES = 13
SLOT_COUNT = 65536
LOGICAL_FIELDS = ("st", "last", "pkts", "bytes")


def run_json(args):
    result = subprocess.run(
        args, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(args)}\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON from command: {' '.join(args)}"
        ) from exc


def find_map_info():
    maps = run_json(["bpftool", "-j", "map", "show"])
    if not isinstance(maps, list):
        raise RuntimeError("Unexpected bpftool map-show output.")

    matches = [item for item in maps if item.get("name") == "flow_state"]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one flow_state map, found {len(matches)}."
        )

    info = matches[0]
    if type(info.get("id")) is not int:
        raise RuntimeError("flow_state map has no numeric ID.")

    expected = {
        "type": "array",
        "max_entries": SLOT_COUNT,
        "bytes_key": 4,
        "bytes_value": RECORD_BYTES,
    }
    for field, value in expected.items():
        if field in info and info[field] != value:
            raise RuntimeError(
                f"Unexpected flow_state {field}: "
                f"{info[field]!r}; expected {value!r}."
            )

    return info


def encode_record(record):
    """Encode one validated logical record into the XDP 40-byte C layout."""
    required = {"slot", "key", "st", "last", "pkts", "bytes"}
    if not isinstance(record, dict) or not required.issubset(record):
        raise ValueError("Record is missing required fields.")

    key = tuple(record["key"])
    encoded_key = key_bytes(key)

    if len(encoded_key) != KEY_BYTES:
        raise ValueError(f"Flow key must serialize to {KEY_BYTES} bytes.")

    slot = record["slot"]
    if type(slot) is not int or not 0 <= slot < SLOT_COUNT:
        raise ValueError("Slot is outside the valid range.")

    if slot_of(key, SLOT_COUNT) != slot:
        raise ValueError("Record slot does not match its flow-key hash.")

    state = record["st"]
    if type(state) is not int or state not in (1, 2, 3):
        raise ValueError("State code must be one of 1, 2, or 3.")

    last = record["last"]
    if type(last) is not int or not 0 <= last < (1 << 48):
        raise OverflowError("Timestamp must fit an unsigned 48-bit value.")

    pkts = record["pkts"]
    byte_count = record["bytes"]
    u64_max = (1 << 64) - 1

    if type(pkts) is not int or not 0 <= pkts <= u64_max:
        raise OverflowError("Packet counter must fit an unsigned 64-bit value.")

    if type(byte_count) is not int or not 0 <= byte_count <= u64_max:
        raise OverflowError("Byte counter must fit an unsigned 64-bit value.")

    raw = bytearray(RECORD_BYTES)
    raw[0:13] = encoded_key
    raw[13] = state
    raw[14] = 1  # valid
    raw[15] = 0  # struct padding
    raw[16:24] = last.to_bytes(8, "little")
    raw[24:32] = pkts.to_bytes(8, "little")
    raw[32:40] = byte_count.to_bytes(8, "little")
    return bytes(raw)

def decode_btf_value(value):
    """Normalize BTF-decoded values into the known 40-byte layout."""
    required = {"key", "st", "valid", "last", "pkts", "bytes"}
    missing = required - set(value)
    if missing:
        raise ValueError(f"Missing BTF fields: {sorted(missing)}")

    key = decode_bytes(value["key"], "flow_record.key")
    if len(key) != KEY_BYTES:
        raise ValueError(f"Expected {KEY_BYTES}-byte key.")

    raw = bytearray(RECORD_BYTES)
    raw[0:13] = key
    raw[13] = parse_integer(value["st"], "st")
    raw[14] = parse_integer(value["valid"], "valid")
    raw[15] = 0

    for field, offset in (("last", 16), ("pkts", 24), ("bytes", 32)):
        raw[offset:offset + 8] = parse_integer(
            value[field], field
        ).to_bytes(8, "little")

    return bytes(raw)


def decode_raw_value(value):
    if isinstance(value, (list, tuple)):
        raw = decode_bytes(value, "flow_record")
    elif isinstance(value, dict):
        raw = decode_btf_value(value)
    else:
        raise ValueError(
            f"Unsupported map value type: {type(value).__name__}."
        )

    if len(raw) != RECORD_BYTES:
        raise ValueError(
            f"Expected {RECORD_BYTES}-byte record, got {len(raw)}."
        )

    return raw


def decode_current_record(slot, raw):
    decoded = decode_record_value(list(raw))
    if decoded is None:
        return None

    return {
        "slot": slot,
        "key": list(decoded["key"]),
        "st": decoded["st"],
        "last": decoded["last"],
        "pkts": decoded["pkts"],
        "bytes": decoded["bytes"],
    }


def read_raw_slot(map_id, slot):
    key = struct.pack("<I", slot)
    result = run_json([
        "bpftool", "-j", "map", "lookup",
        "id", str(map_id),
        "key", "hex",
        *[f"{byte:02x}" for byte in key],
    ])

    if not isinstance(result, dict) or "value" not in result:
        raise RuntimeError(f"Unexpected lookup result for slot {slot}.")

    return decode_raw_value(result["value"])


def read_slots(map_id, slots):
    previous = {}

    for slot in sorted(set(slots)):
        raw = read_raw_slot(map_id, slot)
        previous[slot] = {
            "raw": raw,
            "record": decode_current_record(slot, raw),
        }

    return previous


def plan_import(records, existing_by_slot, replace_same_key=False):
    plans = []
    errors = []

    for wanted in records:
        slot = wanted["slot"]
        entry = existing_by_slot[slot]
        current = entry["record"]

        if current is None:
            plans.append({
                "action": "insert",
                "slot": slot,
                "record": wanted,
            })
            continue

        if current["key"] != wanted["key"]:
            errors.append(
                f"Slot {slot} has a different key. "
                "Different-key collisions cannot be overwritten."
            )
            plans.append({
                "action": "blocked_slot_conflict",
                "slot": slot,
                "record": wanted,
            })
            continue

        differences = {
            field: {
                "destination": current[field],
                "snapshot": wanted[field],
            }
            for field in LOGICAL_FIELDS
            if current[field] != wanted[field]
        }

        if not differences:
            plans.append({
                "action": "noop",
                "slot": slot,
                "record": wanted,
            })
        elif not replace_same_key:
            errors.append(
                f"Slot {slot} has the same key but different state; "
                "use --replace-same-key to permit replacement."
            )
            plans.append({
                "action": "blocked_same_key_difference",
                "slot": slot,
                "record": wanted,
                "differences": differences,
            })
        else:
            plans.append({
                "action": "replace",
                "slot": slot,
                "record": wanted,
                "differences": differences,
            })

    return plans, errors


def update_raw_slot(map_id, slot, raw):
    if len(raw) != RECORD_BYTES:
        raise ValueError("Map update value must be exactly 40 bytes.")

    key = struct.pack("<I", slot)
    args = [
        "bpftool", "map", "update",
        "id", str(map_id),
        "key", "hex",
        *[f"{byte:02x}" for byte in key],
        "value", "hex",
        *[f"{byte:02x}" for byte in raw],
        "any",
    ]

    result = subprocess.run(
        args, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Map update failed at slot {slot}: {result.stderr.strip()}"
        )


def matches(actual, wanted):
    return (
        actual is not None
        and actual["slot"] == wanted["slot"]
        and actual.get("chain_index", 0) == wanted.get("chain_index", 0)
        and actual["key"] == wanted["key"]
        and all(actual[field] == wanted[field] for field in LOGICAL_FIELDS)
    )


def apply_plan(map_id, plans, previous_by_slot):
    changed = [
        plan for plan in plans
        if plan["action"] in {"insert", "replace"}
    ]
    attempted = []

    try:
        for plan in changed:
            slot = plan["slot"]
            wanted = plan["record"]
            attempted.append(slot)

            update_raw_slot(map_id, slot, encode_record(wanted))
            actual_raw = read_raw_slot(map_id, slot)
            actual = decode_current_record(slot, actual_raw)

            if not matches(actual, wanted):
                raise RuntimeError(
                    f"Post-write verification failed at slot {slot}."
                )

    except Exception as exc:
        rollback_errors = []

        for slot in reversed(attempted):
            old_raw = previous_by_slot[slot]["raw"]
            try:
                update_raw_slot(map_id, slot, old_raw)
                restored = read_raw_slot(map_id, slot)
                if restored != old_raw:
                    raise RuntimeError("Restored bytes differ from backup.")
            except Exception as rollback_exc:
                rollback_errors.append(
                    f"slot {slot}: {rollback_exc}"
                )

        message = f"Import failed; rollback was attempted: {exc}"
        if rollback_errors:
            message += "\nROLLBACK ERRORS:\n" + "\n".join(rollback_errors)
        raise RuntimeError(message) from exc

    return len(changed)


def main():
    parser = argparse.ArgumentParser(
        description="Import a CrossState snapshot into the XDP flow_state map."
    )
    parser.add_argument("snapshot", type=Path)
    parser.add_argument(
        "--replace-same-key",
        action="store_true",
        help="Allow replacing state of an already-present identical flow key.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform map writes. Without this option the run is read-only.",
    )
    args = parser.parse_args()

    snapshot_path = args.snapshot
    if not snapshot_path.is_absolute():
        snapshot_path = ROOT / snapshot_path

    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        errors = validate_snapshot(snapshot)
        if errors:
            raise ValueError(
                "Snapshot validation failed:\n- " + "\n- ".join(errors)
            )

        info = find_map_info()
        map_id = info["id"]
        slots = [record["slot"] for record in snapshot["records"]]
        previous = read_slots(map_id, slots)
        plans, errors = plan_import(
            snapshot["records"],
            previous,
            replace_same_key=args.replace_same_key,
        )
    except Exception as exc:
        print(f"XDP_STATE_IMPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    counts = {}
    for plan in plans:
        counts[plan["action"]] = counts.get(plan["action"], 0) + 1

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"========== XDP STATE IMPORT: {mode} ==========")
    print(f"Snapshot source: {snapshot['source_target']}")
    print(f"Map ID: {map_id}")
    print(f"Records inspected: {len(snapshot['records'])}")
    for action in sorted(counts):
        print(f"{action}: {counts[action]}")

    if errors:
        print(f"Preflight errors: {len(errors)}")
        for error in errors:
            print("BLOCKED:", error)
        print("No writes performed.")
        print("XDP_STATE_IMPORT = BLOCKED")
        return 2

    if not args.apply:
        print("No writes performed. Use --apply after reviewing this plan.")
        print("XDP_STATE_IMPORT = DRY_RUN_PASS")
        return 0

    try:
        changed = apply_plan(map_id, plans, previous)
    except Exception as exc:
        print(f"XDP_STATE_IMPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    print(f"Records written and verified: {changed}")
    print("XDP_STATE_IMPORT = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
