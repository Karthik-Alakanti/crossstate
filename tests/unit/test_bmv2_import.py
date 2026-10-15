import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref.model import slot_of
from scripts.import_bmv2_state import (
    build_write_commands,
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
    return build_snapshot("xdp", records)


def current_from(wanted, **overrides):
    result = {
        **wanted,
        "key": list(wanted["key"]),
        "synced": 0,
    }
    result.update(overrides)
    return result


def test_empty_destination_plans_insert():
    wanted = snapshot(record())["records"]
    plans, errors = plan_import(
        {"records": wanted}, {wanted[0]["slot"]: None}
    )

    assert errors == []
    assert plans[0]["action"] == "insert"


def test_identical_destination_record_is_noop():
    wanted = snapshot(record())["records"][0]
    plans, errors = plan_import(
        {"records": [wanted]},
        {wanted["slot"]: current_from(wanted)},
    )

    assert errors == []
    assert plans[0]["action"] == "noop"


def test_same_key_different_state_requires_flag():
    wanted = snapshot(record())["records"][0]
    current = current_from(wanted, last=123)

    plans, errors = plan_import(
        {"records": [wanted]},
        {wanted["slot"]: current},
    )

    assert plans[0]["action"] == "blocked_same_key_difference"
    assert any("--replace-same-key" in error for error in errors)


def test_same_key_replacement_can_be_authorized():
    wanted = snapshot(record())["records"][0]
    current = current_from(wanted, last=123)

    plans, errors = plan_import(
        {"records": [wanted]},
        {wanted["slot"]: current},
        replace_same_key=True,
    )

    assert errors == []
    assert plans[0]["action"] == "replace"


def test_different_key_collision_is_never_overwritten():
    wanted = snapshot(record())["records"][0]
    collision_key = None

    # Find a different flow with the same CRC slot.
    for port in range(1024, 65536):
        candidate = (167772161, port, 167772162, 443, 6)
        if candidate != KEY_A and slot_of(candidate) == wanted["slot"]:
            collision_key = candidate
            break

    if collision_key is None:
        raise AssertionError("Could not find a CRC collision.")

    current = current_from(wanted, key=list(collision_key))

    plans, errors = plan_import(
        {"records": [wanted]},
        {wanted["slot"]: current},
        replace_same_key=True,
    )

    assert plans[0]["action"] == "blocked_slot_conflict"
    assert errors


def test_import_write_sets_valid_last_and_synced_zero():
    wanted = snapshot(record())["records"][0]
    commands = build_write_commands(wanted)

    assert commands[0] == f"register_write r_valid {wanted['slot']} 0"
    assert commands[-1] == f"register_write r_valid {wanted['slot']} 1"
    assert f"register_write r_synced {wanted['slot']} 0" in commands


def test_write_commands_preserve_record_values():
    wanted = snapshot(record())["records"][0]
    commands = build_write_commands(wanted)

    expected = [
        f"register_write r_ipa {wanted['slot']} {KEY_A[0]}",
        f"register_write r_pa {wanted['slot']} {KEY_A[1]}",
        f"register_write r_ipb {wanted['slot']} {KEY_A[2]}",
        f"register_write r_pb {wanted['slot']} {KEY_A[3]}",
        f"register_write r_st {wanted['slot']} {wanted['st']}",
        f"register_write r_last {wanted['slot']} {wanted['last']}",
        f"register_write r_pkts {wanted['slot']} {wanted['pkts']}",
        f"register_write r_bytes {wanted['slot']} {wanted['bytes']}",
    ]
    for command in expected:
        assert command in commands
