import copy
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.generate_contract import build_contract, serialize_contract


def load_spec():
    with (ROOT / "spec/firewall.yaml").open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_contract_matches_specification():
    spec = load_spec()
    contract = build_contract(spec)

    assert contract["spec"]["table"]["slots"] == spec["slots"]
    assert contract["spec"]["table"]["idle_timeout_us"] == spec["idle_timeout_us"]
    assert contract["runtime_contract"]["flow_key"]["serialized_length_bytes"] == 13
    assert contract["runtime_contract"]["state_codes"] == {
        "NEW": 1,
        "EST": 2,
        "CLOSED": 3,
    }


def test_contract_serialization_is_deterministic():
    spec = load_spec()
    first = serialize_contract(build_contract(spec))
    second = serialize_contract(build_contract(copy.deepcopy(spec)))

    assert first == second
    assert json.loads(first)["format"] == "crossstate-runtime-contract"


def test_generator_rejects_invalid_specification():
    spec = load_spec()
    spec["collision"] = "overwrite"

    try:
        build_contract(spec)
    except ValueError as exc:
        assert "collision" in str(exc)
    else:
        raise AssertionError("Invalid specification was accepted")
