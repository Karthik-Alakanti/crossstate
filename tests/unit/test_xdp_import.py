import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref.model import key_bytes, slot_of
from scripts.import_xdp_state import (
    RECORD_BYTES,
    encode_record,
    decode_current_record,
    plan_import,
)
from scripts.state_snapshot import build_snapshot

KEY_A = (577090037, 37303, 3639700191, 52577, 6)
KEY_B = (167772161, 40000, 167772162, 443, 6)


def record(key=KEY_A, **overrides):
    result = {
        "slot": slot_of(key),
        "key": list(key),
        "st": 2,
        "last": 4_000_001,
        "pkts": 7,
        "bytes": 280,
    }
    result.update(overrides)
    return result


def snapshot(*records):
    return build_snapshot("bmv2", records)


def existing(wanted, **changes):
    current = dict(wanted)
    current["key"] = list(wanted["key"])
    current.update(changes)
    return {
        "raw": b"\x00" * RECORD_BYTES,
        "record": current,
    }


def test_encode_record_matches_40_byte_c_layout():
    item = record()
    raw = encode_record(item)

    assert len(raw) == 40
    assert raw[:13] == key_bytes(KEY_A)
    assert raw[13] == 2
    assert raw[14] == 1
    assert raw[15] == 0
    assert int.from_bytes(raw[16:24], "little") == item["last"]
    assert int.from_bytes(raw[24:32], "little") == item["pkts"]
    assert int.from_bytes(raw[32:40], "little") == item["bytes"]


def test_encoded_record_decodes_to_same_logical_state():
    item = record()
    raw = encode_record(item)
    decoded = decode_current_record(item["slot"], raw)

    assert decoded == item


def test_empty_slot_plans_insert():
    item = snapshot(record())["records"][0]
    plans, errors = plan_import(
        [item],
        {item["slot"]: {"raw": b"\x00" * 40, "record": None}},
    )

    assert errors == []
    assert plans[0]["action"] == "insert"


def test_identical_state_is_noop():
    item = snapshot(record())["records"][0]
    plans, errors = plan_import(
        [item],
        {item["slot"]: existing(item)},
    )

    assert errors == []
    assert plans[0]["action"] == "noop"


def test_changed_state_requires_explicit_replace():
    item = snapshot(record())["records"][0]
    plans, errors = plan_import(
        [item],
        {item["slot"]: existing(item, last=123)},
    )

    assert plans[0]["action"] == "blocked_same_key_difference"
    assert any("--replace-same-key" in error for error in errors)


def test_same_key_replacement_can_be_authorized():
    item = snapshot(record())["records"][0]
    plans, errors = plan_import(
        [item],
        {item["slot"]: existing(item, pkts=99)},
        replace_same_key=True,
    )

    assert errors == []
    assert plans[0]["action"] == "replace"


def test_different_key_slot_collision_is_blocked():
    item = snapshot(record())["records"][0]
    collision = None

    for port in range(1024, 65536):
        candidate = (167772161, port, 167772162, 443, 6)
        if candidate != KEY_A and slot_of(candidate) == item["slot"]:
            collision = candidate
            break

    if collision is None:
        raise AssertionError("Could not find a CRC slot collision.")

    plans, errors = plan_import(
        [item],
        {item["slot"]: existing(item, key=list(collision))},
        replace_same_key=True,
    )

    assert plans[0]["action"] == "blocked_slot_conflict"
    assert errors


def test_record_encodes_maximum_uint64_counter():
    item = record(pkts=(1 << 64) - 1)
    raw = encode_record(item)

    assert int.from_bytes(raw[24:32], "little") == (1 << 64) - 1


def test_record_rejects_timestamp_outside_48_bit_snapshot_range():
    item = record(last=1 << 48)

    with pytest.raises(OverflowError):
        encode_record(item)
