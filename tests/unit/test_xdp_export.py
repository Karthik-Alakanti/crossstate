import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ref.model import key_bytes, slot_of
from scripts.export_xdp_state import (
    decode_map_entry,
    decode_record_value,
    export_records,
)


KEY = (577090037, 37303, 3639700191, 52577, 6)


def raw_record(
    key=KEY, st=2, valid=1, last=4_000_001, pkts=7, bytes_count=280
):
    raw = bytearray(40)
    raw[0:13] = key_bytes(key)
    raw[13] = st
    raw[14] = valid
    raw[16:24] = last.to_bytes(8, "little")
    raw[24:32] = pkts.to_bytes(8, "little")
    raw[32:40] = bytes_count.to_bytes(8, "little")
    return list(raw)


def map_entry(slot, value):
    return {
        "key": list(slot.to_bytes(4, "little")),
        "value": value,
    }


def test_decodes_xdp_record_layout():
    decoded = decode_record_value(raw_record())

    assert decoded == {
        "key": KEY,
        "st": 2,
        "last": 4_000_001,
        "pkts": 7,
        "bytes": 280,
    }


def test_skips_invalid_array_slots():
    assert decode_record_value(raw_record(valid=0)) is None


def test_rejects_wrong_record_size():
    with pytest.raises(ValueError, match="40-byte"):
        decode_record_value([0] * 39)


def test_map_entry_slot_and_record_are_preserved():
    slot = slot_of(KEY)
    decoded = decode_map_entry(map_entry(slot, raw_record()))

    assert decoded["slot"] == slot
    assert decoded["key"] == KEY
    assert decoded["pkts"] == 7


def test_rejects_invalid_map_key_size():
    entry = {"key": [0, 0, 0], "value": raw_record()}

    with pytest.raises(ValueError, match="4-byte"):
        decode_map_entry(entry)


def test_export_records_ignores_empty_slots():
    slot = slot_of(KEY)
    records, entries_read = export_records([
        map_entry(slot, raw_record()),
        map_entry(0, raw_record(valid=0)),
    ])

    assert entries_read == 2
    assert len(records) == 1
    assert records[0]["slot"] == slot


def test_export_records_rejects_incompatible_record():
    with pytest.raises(ValueError, match="Map entry 0"):
        export_records([map_entry(slot_of(KEY), [0] * 39)])
