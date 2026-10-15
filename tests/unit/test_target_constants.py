import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.generate_target_constants import render_outputs


def load_contract():
    path = ROOT / "artifacts/generated/firewall_contract.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_generated_constants_match_runtime_contract():
    contract = load_contract()
    outputs = render_outputs(contract)

    p4 = outputs["p4/firewall_constants.p4"]
    c = outputs["ebpf/firewall_constants.h"]

    assert "#define CS_SLOT_COUNT 65536" in p4
    assert "#define CS_IDLE_TIMEOUT_US 48w30000000" in p4
    assert "#define CS_ST_NEW 8w1" in p4

    assert "#define CS_SLOT_COUNT 65536U" in c
    assert "#define CS_IDLE_TIMEOUT_US 30000000ULL" in c
    assert "#define CS_ST_CLOSED 3U" in c


def test_generation_is_deterministic():
    contract = load_contract()

    assert render_outputs(contract) == render_outputs(copy.deepcopy(contract))


def test_generator_rejects_state_code_drift():
    contract = load_contract()
    contract["runtime_contract"]["state_codes"]["NEW"] = 9

    with pytest.raises(ValueError, match="state codes disagree"):
        render_outputs(contract)


def test_generator_rejects_key_length_drift():
    contract = load_contract()
    contract["runtime_contract"]["flow_key"]["serialized_length_bytes"] = 12

    with pytest.raises(ValueError, match="Key length mismatch"):
        render_outputs(contract)
