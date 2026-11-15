from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def test_p4_uses_generated_constants():
    source = (ROOT / "p4/firewall.p4").read_text(encoding="utf-8")

    assert '#include "firewall_constants.p4"' in source
    assert "register<bit<1>>(CS_SLOT_COUNT)" in source
    assert "CS_SLOT_COUNT_B32" in source
    assert "T_US = CS_IDLE_TIMEOUT_US" in source
    assert "NEW    = CS_ST_NEW" in source
    assert "EST    = CS_ST_EST" in source
    assert "CLOSED = CS_ST_CLOSED" in source
    assert re.search(r"register<[^>]+>\(65536\)", source) is None
    assert "32w65536" not in source
    assert "48w30000000" not in source


def test_xdp_uses_generated_constants():
    source = (ROOT / "ebpf/firewall_xdp.c").read_text(encoding="utf-8")

    assert '#include "firewall_constants.h"' in source
    assert "CS_SLOT_COUNT" in source
    assert "CS_KEY_LEN" in source
    assert "CS_IDLE_TIMEOUT_US" in source
    assert "CS_ST_NEW" in source
    assert "CS_ST_EST" in source
    assert "CS_ST_CLOSED" in source
    assert "#define MAX_SLOTS          65536U" not in source
    assert "#define IDLE_TIMEOUT_US    30000000ULL" not in source
