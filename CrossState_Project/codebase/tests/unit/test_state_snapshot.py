import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref.model import slot_of
from scripts.state_snapshot import (
    FORMAT,
    SLOT_COUNT,
    build_snapshot,
    serialize_snapshot,
    validate_snapshot,
)


KEY = [577090037, 37303, 3639700191, 52577, 6]


def record(key=None, **overrides):
    key = list(KEY if key is None else key)
    result = {
        "slot": slot_of(tuple(key), SLOT_COUNT),
        "key": key,
        "st": 2,
        "last": 4_000_001,
        "pkts": 7,
        "bytes": 280,
    }
    result.update(overrides)
    return result


def snapshot(*records):
    return build_snapshot("offline", records)


def test_valid_snapshot_and_round_trip():
    original = snapshot(record())
    encoded = serialize_snapshot(original)
    restored = json.loads(encoded)

    assert validate_snapshot(restored) == []
    assert restored == original
    assert restored["format"] == FORMAT


def test_builder_sorts_records_by_slot():
    key2 = [167772161, 40000, 167772162, 443, 6]
    first = record()
    second = record(key2)

    built = snapshot(first, second)

    slots = [item["slot"] for item in built["records"]]
    assert slots == sorted(slots)


def test_rejects_wrong_slot():
    item = record()
    item["slot"] = (item["slot"] + 1) % SLOT_COUNT

    errors = validate_snapshot({
        "format": FORMAT,
        "schema_version": 1,
        "spec_name": "tcp_firewall",
        "spec_version": 1,
        "slots": SLOT_COUNT,
        "source_target": "xdp",
        "records": [item],
    })

    assert any("slot mismatch" in error for error in errors)


def test_rejects_noncanonical_key():
    reversed_key = [
        KEY[2], KEY[3], KEY[0], KEY[1], KEY[4]
    ]
    item = record(reversed_key)

    malformed = {
        "format": FORMAT,
        "schema_version": 1,
        "spec_name": "tcp_firewall",
        "spec_version": 1,
        "slots": SLOT_COUNT,
        "source_target": "xdp",
        "records": [item],
    }

    errors = validate_snapshot(malformed)

    assert any("canonical endpoint order" in error for error in errors)


def test_rejects_invalid_state_and_numeric_widths():
    valid = snapshot(record())

    invalid_state = copy.deepcopy(valid)
    invalid_state["records"][0]["st"] = 9
    assert any(
        ".st must be" in error
        for error in validate_snapshot(invalid_state)
    )

    invalid_timestamp = copy.deepcopy(valid)
    invalid_timestamp["records"][0]["last"] = 1 << 48
    assert any(
        ".last must fit" in error
        for error in validate_snapshot(invalid_timestamp)
    )

    invalid_counter = copy.deepcopy(valid)
    invalid_counter["records"][0]["pkts"] = 1 << 64
    assert any(
        ".pkts must fit" in error
        for error in validate_snapshot(invalid_counter)
    )


def test_rejects_duplicate_slots_and_keys():
    item = record()
    malformed = {
        "format": FORMAT,
        "schema_version": 1,
        "spec_name": "tcp_firewall",
        "spec_version": 1,
        "slots": SLOT_COUNT,
        "source_target": "xdp",
        "records": [item, copy.deepcopy(item)],
    }

    errors = validate_snapshot(malformed)

    assert any("duplicates slot" in error for error in errors)
    assert any("duplicates another record" in error for error in errors)


def test_rejects_unknown_schema_version():
    valid = snapshot(record())
    valid["schema_version"] = 2

    errors = validate_snapshot(valid)

    assert any("schema_version must be 1" in error for error in errors)


def test_builder_rejects_record_with_wrong_slot():
    item = record()
    item["slot"] = 42

    with pytest.raises(ValueError, match="slot mismatch"):
        snapshot(item)
