import copy
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.validate_spec import validate_spec


def load_spec():
    with (ROOT / "spec" / "firewall.yaml").open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def test_current_spec_matches_reference_contract():
    assert validate_spec(load_spec()) == []


def test_rejects_wrong_hash():
    spec = copy.deepcopy(load_spec())
    spec["hash"] = "crc32_wrong_format"

    errors = validate_spec(spec)

    assert any("hash" in error for error in errors)


def test_rejects_wrong_timeout():
    spec = copy.deepcopy(load_spec())
    spec["idle_timeout_us"] = 10_000_000

    errors = validate_spec(spec)

    assert any("idle_timeout_us" in error for error in errors)


def test_rejects_wrong_key_order():
    spec = copy.deepcopy(load_spec())
    spec["key"] = [
        "ip_a", "ip_b", "port_a", "port_b", "proto"
    ]

    errors = validate_spec(spec)

    assert any("key" in error for error in errors)


def test_rejects_wrong_state_enum():
    spec = copy.deepcopy(load_spec())
    spec["value"]["st"]["enum"] = ["NEW", "CLOSED", "EST"]

    errors = validate_spec(spec)

    assert any("value.st.enum" in error for error in errors)


def test_rejects_wrong_counter_width():
    spec = copy.deepcopy(load_spec())
    spec["value"]["pkts"] = "u32"

    errors = validate_spec(spec)

    assert any("value.pkts" in error for error in errors)


def test_rejects_wrong_collision_policy():
    spec = copy.deepcopy(load_spec())
    spec["collision"] = "overwrite"

    errors = validate_spec(spec)

    assert any("collision" in error for error in errors)
