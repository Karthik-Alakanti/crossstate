import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.export_bmv2_state import (
    parse_indexed_registers,
    parse_register_array,
)


def test_parse_small_full_register_array():
    output = (
        "Obtaining JSON from switch...\n"
        "Done\n"
        "RuntimeCmd: r_valid= 0, 1, 0, 1\n"
        "RuntimeCmd: "
    )

    assert parse_register_array(output, "r_valid", 4) == [0, 1, 0, 1]


def test_rejects_wrong_full_array_size():
    output = "RuntimeCmd: r_valid= 0, 1\nRuntimeCmd: "

    with pytest.raises(ValueError, match="expected 3"):
        parse_register_array(output, "r_valid", 3)


def test_rejects_missing_register_response():
    with pytest.raises(ValueError, match="Could not find"):
        parse_register_array("RuntimeCmd: ", "r_valid", 2)


def test_parse_indexed_register_responses():
    output = (
        "RuntimeCmd: r_valid[42]= 1\n"
        "RuntimeCmd: r_ipa[42]= 577090037\n"
        "RuntimeCmd: r_st[42]= 2\n"
        "RuntimeCmd: "
    )

    parsed = parse_indexed_registers(
        output,
        [("r_valid", 42), ("r_ipa", 42), ("r_st", 42)],
    )

    assert parsed[("r_valid", 42)] == 1
    assert parsed[("r_ipa", 42)] == 577090037
    assert parsed[("r_st", 42)] == 2


def test_rejects_missing_indexed_response():
    with pytest.raises(ValueError, match="found 0"):
        parse_indexed_registers("RuntimeCmd: ", [("r_st", 42)])
