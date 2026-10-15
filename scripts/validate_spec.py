#!/usr/bin/env python3
"""Validate the CrossState v1 firewall specification and reference contract."""

import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import yaml
except ImportError:
    raise SystemExit(
        "Missing PyYAML. Install it with: python -m pip install pyyaml"
    )

from ref import model
from ref.model import Ev, canon, key_bytes, slot_of, step


EXPECTED_SCALARS = {
    "name": "tcp_firewall",
    "version": 1,
    "slots": 65536,
    "buckets": 64,
    "hash": "crc32_13B_be",
    "clock": "shim_us",
    "idle_timeout_us": 30_000_000,
    "collision": "reject",
    "expiry": "lazy",
}

EXPECTED_KEY = [
    "ip_a",
    "port_a",
    "ip_b",
    "port_b",
    "proto",
]

EXPECTED_STATES = ["NEW", "EST", "CLOSED"]

EXPECTED_VALUE = {
    "last": "u48",
    "pkts": "u64",
    "bytes": "u64",
}

EXPECTED_TOP_LEVEL = set(EXPECTED_SCALARS) | {"key", "value"}


def validate_spec(spec):
    errors = []

    def fail(message):
        errors.append(message)

    if not isinstance(spec, dict):
        return ["The YAML document root must be a mapping."]

    extra = set(spec) - EXPECTED_TOP_LEVEL
    missing = EXPECTED_TOP_LEVEL - set(spec)

    if extra:
        fail(f"Unexpected top-level fields: {sorted(extra)}")
    if missing:
        fail(f"Missing top-level fields: {sorted(missing)}")

    for field, expected in EXPECTED_SCALARS.items():
        actual = spec.get(field)

        # bool is a subclass of int in Python, so check integer fields
        # explicitly to reject values such as version: true.
        if field in ("version", "slots", "buckets", "idle_timeout_us"):
            if type(actual) is not int:
                fail(f"{field} must be an integer; got {actual!r}.")
                continue

        if actual != expected:
            fail(
                f"{field} must be {expected!r}; got {actual!r}."
            )

    slots = spec.get("slots")
    buckets = spec.get("buckets")

    if type(slots) is int and slots > 0:
        if slots & (slots - 1):
            fail("slots must be a positive power of two.")
    elif type(slots) is int:
        fail("slots must be positive.")

    if type(buckets) is int and buckets > 0:
        if type(slots) is int and slots > 0 and slots % buckets != 0:
            fail("buckets must divide slots evenly.")
    elif type(buckets) is int:
        fail("buckets must be positive.")

    if spec.get("key") != EXPECTED_KEY:
        fail(
            "key must use the canonical layout "
            f"{EXPECTED_KEY!r}; got {spec.get('key')!r}."
        )

    value = spec.get("value")

    if not isinstance(value, dict):
        fail("value must be a mapping.")
    else:
        if set(value) != {"st", "last", "pkts", "bytes"}:
            fail("value must contain exactly st, last, pkts, and bytes.")

        state_field = value.get("st")
        if not isinstance(state_field, dict):
            fail("value.st must be a mapping containing enum.")
        elif (
            set(state_field) != {"enum"}
            or state_field.get("enum") != EXPECTED_STATES
        ):
            fail(
                "value.st.enum must be "
                f"{EXPECTED_STATES!r}; got {state_field!r}."
            )

        for field, expected_type in EXPECTED_VALUE.items():
            actual_type = value.get(field)
            if actual_type != expected_type:
                fail(
                    f"value.{field} must be {expected_type!r}; "
                    f"got {actual_type!r}."
                )

    # Compare YAML configuration with the Python reference constants.
    if type(slots) is int and slots != model.N:
        fail(f"Reference model N={model.N} does not match slots={slots}.")

    timeout = spec.get("idle_timeout_us")
    if type(timeout) is int and timeout != model.T:
        fail(
            f"Reference model T={model.T} does not match "
            f"idle_timeout_us={timeout}."
        )

    enum_values = (model.NEW, model.EST, model.CLOSED)
    if enum_values != (1, 2, 3):
        fail(f"Unexpected reference-model state values: {enum_values!r}.")

    if model.M64 != (1 << 64) - 1:
        fail("Reference model's counter mask is not uint64.")

    # Test canonical endpoint order, network byte order, and CRC32 slot.
    sample = Ev(
        sip=0xA1B2C3D4,
        sport=443,
        dip=0x01020304,
        dport=12345,
        proto=6,
        inside=True,
        syn=True,
        ack=False,
        fin=False,
        rst=False,
        length=40,
        ts=100,
    )

    expected_key = (
        0x01020304,
        12345,
        0xA1B2C3D4,
        443,
        6,
    )
    expected_hex = "010203043039a1b2c3d401bb06"
    actual_key = canon(sample)

    if actual_key != expected_key:
        fail(
            f"Canonicalization mismatch: {actual_key!r} "
            f"!= {expected_key!r}."
        )

    encoded = key_bytes(expected_key)

    if len(encoded) != 13:
        fail(f"Encoded flow key must be 13 bytes; got {len(encoded)}.")

    if encoded.hex() != expected_hex:
        fail(
            f"Network-byte-order mismatch: {encoded.hex()} "
            f"!= {expected_hex}."
        )

    if type(slots) is int and slots > 0:
        expected_slot = zlib.crc32(encoded) % slots
        actual_slot = slot_of(expected_key, slots)

        if actual_slot != expected_slot:
            fail(
                f"CRC slot mismatch: {actual_slot} != {expected_slot}."
            )

    # Check the reference model's timeout boundary and lazy expiry.
    # At exactly T microseconds, the existing flow must still be live.
    # At T+1, a non-SYN packet must be dropped, leaving the stale record
    # unchanged (lazy expiration).
    if type(slots) is int and slots > 0 and type(timeout) is int and timeout > 0:
        init = Ev(
            0x0A000001, 12345, 0x0A000002, 443, 6,
            True, True, False, False, False, 40, 100,
        )
        ack_at_boundary = Ev(
            0x0A000001, 12345, 0x0A000002, 443, 6,
            True, False, True, False, False, 40, 100 + timeout,
        )
        ack_after_timeout = Ev(
            0x0A000001, 12345, 0x0A000002, 443, 6,
            True, False, True, False, False, 40, 101 + timeout,
        )

        boundary_table = {}
        first_decision = step(boundary_table, init, n=slots, t=timeout)
        boundary_decision = step(
            boundary_table, ack_at_boundary, n=slots, t=timeout
        )

        if first_decision != model.ALLOW:
            fail("Reference-model timeout check: initial SYN was not allowed.")

        if boundary_decision != model.ALLOW:
            fail("Reference model must treat elapsed time == timeout as live.")

        key = canon(init)
        slot = slot_of(key, slots)

        expiry_table = {}
        step(expiry_table, init, n=slots, t=timeout)
        original_record = expiry_table[slot]
        expiry_decision = step(
            expiry_table, ack_after_timeout, n=slots, t=timeout
        )

        if expiry_decision != model.DROP:
            fail("Reference model must drop a non-SYN packet after timeout.")

        if expiry_table[slot] != original_record:
            fail("Lazy expiry must leave the stale record unchanged here.")

    return errors


def main():
    spec_path = ROOT / "spec" / "firewall.yaml"

    try:
        with spec_path.open(encoding="utf-8") as file:
            spec = yaml.safe_load(file)
    except Exception as exc:
        print(f"FAIL: Could not load {spec_path}: {exc}", file=sys.stderr)
        return 2

    errors = validate_spec(spec)

    print("========== CROSSSTATE SPEC VALIDATION ==========")
    print(f"Specification: {spec_path.relative_to(ROOT)}")

    if errors:
        print(f"Result: FAIL ({len(errors)} issue(s))")
        for index, error in enumerate(errors, start=1):
            print(f"{index}. {error}")
        return 1

    print("PASS: Specification structure and v1 configuration")
    print("PASS: Canonical flow-key field order")
    print("PASS: 13-byte big-endian flow-key encoding")
    print("PASS: CRC32 slot calculation")
    print("PASS: Reference-model slot count and timeout")
    print("PASS: State enumeration and uint64 counter mask")
    print("PASS: Timeout boundary and lazy-expiry behavior")
    print("CROSSSTATE_SPEC_VALIDATION = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
