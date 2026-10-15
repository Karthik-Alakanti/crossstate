import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref.model import slot_of
from scripts.compare_state_snapshots import compare_snapshots
from scripts.state_snapshot import build_snapshot


KEY_A = (577090037, 37303, 3639700191, 52577, 6)
KEY_B = (167772161, 40000, 167772162, 443, 6)


def record(key=KEY_A, **overrides):
    result = {
        "slot": slot_of(key),
        "key": key,
        "st": 2,
        "last": 4_000_001,
        "pkts": 7,
        "bytes": 280,
    }
    result.update(overrides)
    return result


def snap(target, *records):
    return build_snapshot(target, records)


def test_identical_snapshots_are_equivalent():
    left = snap("bmv2", record())
    right = snap("xdp", record())

    report = compare_snapshots(left, right)

    assert report["equivalent"]
    assert len(report["exact_matches"]) == 1
    assert not report["slot_conflicts"]


def test_counter_difference_is_detected():
    left = snap("bmv2", record())
    right = snap("xdp", record(pkts=8))

    report = compare_snapshots(left, right)

    assert not report["equivalent"]
    assert report["differing_records"][0]["differences"]["pkts"] == {
        "left": 7,
        "right": 8,
    }


def test_records_in_only_one_snapshot_are_reported():
    left = snap("bmv2", record())
    right = snap("xdp", record(KEY_B))

    report = compare_snapshots(left, right)

    assert not report["equivalent"]
    assert report["left_only_slots"] == [slot_of(KEY_A)]
    assert report["right_only_slots"] == [slot_of(KEY_B)]


def test_same_slot_different_keys_are_conflicts():
    # Find a distinct canonical key that hashes to KEY_A's slot.
    target_slot = slot_of(KEY_A)
    collision = None

    for port in range(1024, 65536):
        candidate = (
            167772161, port,
            167772162, 443, 6,
        )
        if candidate != KEY_A and slot_of(candidate) == target_slot:
            collision = candidate
            break

    if collision is None:
        raise AssertionError("Could not find deterministic CRC slot collision.")

    left = snap("bmv2", record(KEY_A))
    right = snap("xdp", record(collision))

    report = compare_snapshots(left, right)

    assert not report["equivalent"]
    assert len(report["slot_conflicts"]) == 1
    assert report["slot_conflicts"][0]["slot"] == target_slot
