#!/usr/bin/env python3
"""Versioned, target-independent CrossState state snapshots."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import key_bytes, slot_of

FORMAT = "crossstate-state-snapshot"
SCHEMA_VERSION = 1
SPEC_NAME = "tcp_firewall"
SPEC_VERSION = 1
SLOT_COUNT = 65536

U8_MAX = (1 << 8) - 1
U16_MAX = (1 << 16) - 1
U32_MAX = (1 << 32) - 1
U48_MAX = (1 << 48) - 1
U64_MAX = (1 << 64) - 1

VALID_STATES = {1, 2, 3}
VALID_TARGETS = {"offline", "bmv2", "xdp"}

SNAPSHOT_FIELDS = {
    "format",
    "schema_version",
    "spec_name",
    "spec_version",
    "slots",
    "source_target",
    "records",
}

RECORD_FIELDS = {"slot", "key", "st", "last", "pkts", "bytes"}


def _is_uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_snapshot(snapshot):
    """Return a list of validation errors; an empty list means valid."""
    errors = []

    def fail(message):
        errors.append(message)

    if not isinstance(snapshot, dict):
        return ["Snapshot root must be a JSON object."]

    if set(snapshot) != SNAPSHOT_FIELDS:
        missing = SNAPSHOT_FIELDS - set(snapshot)
        extra = set(snapshot) - SNAPSHOT_FIELDS
        if missing:
            fail(f"Missing snapshot fields: {sorted(missing)}")
        if extra:
            fail(f"Unexpected snapshot fields: {sorted(extra)}")

    expected_header = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "spec_name": SPEC_NAME,
        "spec_version": SPEC_VERSION,
        "slots": SLOT_COUNT,
    }

    for field, expected in expected_header.items():
        actual = snapshot.get(field)

        if field in {"schema_version", "spec_version", "slots"}:
            if type(actual) is not int:
                fail(f"{field} must be an integer.")
                continue

        if actual != expected:
            fail(f"{field} must be {expected!r}; got {actual!r}.")

    source = snapshot.get("source_target")
    if source not in VALID_TARGETS:
        fail(f"source_target must be one of {sorted(VALID_TARGETS)}.")

    records = snapshot.get("records")
    if not isinstance(records, list):
        fail("records must be a JSON array.")
        return errors

    seen_slots = set()
    seen_keys = set()

    for i, rec in enumerate(records):
        prefix = f"records[{i}]"

        if not isinstance(rec, dict):
            fail(f"{prefix} must be a JSON object.")
            continue

        if set(rec) != RECORD_FIELDS:
            missing = RECORD_FIELDS - set(rec)
            extra = set(rec) - RECORD_FIELDS
            if missing:
                fail(f"{prefix} missing fields: {sorted(missing)}")
            if extra:
                fail(f"{prefix} has unexpected fields: {sorted(extra)}")
            continue

        slot = rec["slot"]
        key = rec["key"]

        if not _is_uint(slot, SLOT_COUNT - 1):
            fail(f"{prefix}.slot must be in [0, {SLOT_COUNT - 1}].")
            continue

        if not isinstance(key, list) or len(key) != 5:
            fail(f"{prefix}.key must contain five integer fields.")
            continue

        ia, pa, ib, pb, proto = key
        ranges = (
            ("ip_a", ia, U32_MAX),
            ("port_a", pa, U16_MAX),
            ("ip_b", ib, U32_MAX),
            ("port_b", pb, U16_MAX),
            ("proto", proto, U8_MAX),
        )

        key_ok = True
        for name, value, maximum in ranges:
            if not _is_uint(value, maximum):
                fail(f"{prefix}.key.{name} is outside its unsigned range.")
                key_ok = False

        if not key_ok:
            continue

        # v1 canonicalizes endpoints by (IPv4 address << 16) | port.
        endpoint_a = (ia << 16) | pa
        endpoint_b = (ib << 16) | pb

        if endpoint_a > endpoint_b:
            fail(f"{prefix}.key is not in canonical endpoint order.")

        key_tuple = tuple(key)

        try:
            encoded = key_bytes(key_tuple)
            expected_slot = slot_of(key_tuple, SLOT_COUNT)
        except (OverflowError, ValueError) as exc:
            fail(f"{prefix}.key cannot be serialized: {exc}")
            continue

        if len(encoded) != 13:
            fail(f"{prefix}.key must serialize to exactly 13 bytes.")

        if slot != expected_slot:
            fail(
                f"{prefix}.slot mismatch: supplied {slot}, "
                f"calculated {expected_slot}."
            )

        if slot in seen_slots:
            fail(f"{prefix}.slot duplicates slot {slot}.")
        seen_slots.add(slot)

        if key_tuple in seen_keys:
            fail(f"{prefix}.key duplicates another record.")
        seen_keys.add(key_tuple)

        if type(rec["st"]) is not int or rec["st"] not in VALID_STATES:
            fail(f"{prefix}.st must be one of {sorted(VALID_STATES)}.")

        if not _is_uint(rec["last"], U48_MAX):
            fail(f"{prefix}.last must fit an unsigned 48-bit timestamp.")

        if not _is_uint(rec["pkts"], U64_MAX):
            fail(f"{prefix}.pkts must fit an unsigned 64-bit counter.")

        if not _is_uint(rec["bytes"], U64_MAX):
            fail(f"{prefix}.bytes must fit an unsigned 64-bit counter.")

    return errors


def build_snapshot(source_target, records):
    """Build a deterministic snapshot from normalized logical records."""
    if source_target not in VALID_TARGETS:
        raise ValueError(f"Unsupported source target: {source_target!r}")

    snapshot_records = []

    for record in records:
        snapshot_records.append({
            "slot": record["slot"],
            "key": list(record["key"]),
            "st": record["st"],
            "last": record["last"],
            "pkts": record["pkts"],
            "bytes": record["bytes"],
        })

    snapshot_records.sort(key=lambda rec: rec["slot"])

    snapshot = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "spec_name": SPEC_NAME,
        "spec_version": SPEC_VERSION,
        "slots": SLOT_COUNT,
        "source_target": source_target,
        "records": snapshot_records,
    }

    errors = validate_snapshot(snapshot)
    if errors:
        raise ValueError("Invalid snapshot:\n- " + "\n- ".join(errors))

    return snapshot


def serialize_snapshot(snapshot):
    errors = validate_snapshot(snapshot)
    if errors:
        raise ValueError("Invalid snapshot:\n- " + "\n- ".join(errors))

    return json.dumps(
        snapshot,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    ) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Validate a CrossState state snapshot."
    )
    parser.add_argument("snapshot", type=Path, help="Snapshot JSON file")
    args = parser.parse_args()

    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"SNAPSHOT_VALIDATION = FAIL\nCannot read snapshot: {exc}")
        return 2

    errors = validate_snapshot(snapshot)

    if errors:
        print(f"SNAPSHOT_VALIDATION = FAIL ({len(errors)} issue(s))")
        for error in errors:
            print("-", error)
        return 1

    print("Format: CrossState state snapshot v1")
    print("Source target:", snapshot["source_target"])
    print("Valid records:", len(snapshot["records"]))
    print("SNAPSHOT_VALIDATION = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
