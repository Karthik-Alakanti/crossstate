#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="$HOME/venvs/crossstate/bin/python"
[[ -x "$PY" ]] || { echo "ERROR: CrossState venv missing"; exit 2; }

VENV_SITE="$("$PY" -c 'import site; print(site.getsitepackages()[0])')"
export PYTHONPATH="$ROOT:$VENV_SITE"

APPLY=0
QUIESCED=0
SKIP_TESTS=0

while (($#)); do
    case "$1" in
        --checkpoint-apply) APPLY=1 ;;
        --traffic-quiesced) QUIESCED=1 ;;
        --skip-tests) SKIP_TESTS=1 ;;
        -h|--help)
            echo "Usage: bash scripts/crossstate_master_demo.sh [--skip-tests] [--checkpoint-apply --traffic-quiesced]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 2 ;;
    esac
    shift
done

if (( APPLY && ! QUIESCED )); then
    echo "ERROR: checkpoint apply requires --traffic-quiesced"
    exit 2
fi

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

fail() {
    echo "DEMO STOPPED: $1" >&2
    echo "No automatic target restart or reset was attempted." >&2
    exit 3
}

section "CROSSSTATE MASTER DEMONSTRATION"
echo "Repository: $ROOT"
echo "Commit: $(git rev-parse --short HEAD)"
echo "Mode: $([[ $APPLY == 1 ]] && echo CHECKPOINT-APPLY || echo SAFE-DRY-RUN)"

section "1. RUNTIME PREFLIGHT"

for cmd in ip ss bpftool; do
    command -v "$cmd" >/dev/null || fail "$cmd is missing"
done

for iface in cs-host cs-bmv2 cs-xdp-host cs-xdp; do
    ip link show dev "$iface" >/dev/null 2>&1 || fail "$iface is missing"
done

sudo ss -lntp | grep ':9090' >/dev/null || fail "BMv2 Thrift unavailable"
sudo bpftool net show | grep 'cs-xdp' >/dev/null || fail "XDP is not attached"
sudo bpftool map show | grep 'flow_state' >/dev/null || fail "flow_state map missing"

"$PY" -c 'import scapy.all, pytest; print("Python dependencies: PASS")'

echo "BMv2: PASS"
echo "XDP: PASS"
echo "Veth interfaces: PASS"
echo "Thrift: PASS"

if (( ! SKIP_TESTS )); then
    section "2. REGRESSION TESTS"
    "$PY" -m pytest tests -q
fi

section "3. LIVE PACKET DEMONSTRATION"

sudo env PYTHONPATH="$PYTHONPATH" "$PY" - <<'PY'
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import (
    AsyncSniffer, Ether, IP, TCP, Raw,
    get_if_hwaddr, sendp
)

from scripts import import_bmv2_state as bm
from scripts import import_xdp_state as xd
from scripts import sync_state

ROOT = Path.cwd()
STATE = ROOT / "artifacts/state"
STATE.mkdir(parents=True, exist_ok=True)

THRIFT = 9090
SLOT = 42228
KEY = [174260225, 49153, 174260226, 443, 6]

SRC, DST = "10.99.0.1", "10.99.0.2"
SPORT, DPORT = 49153, 443

stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
prefix = STATE / f"master_demo_{stamp}"

print("Narration: CrossState implements one firewall state contract")
print("across P4/BMv2 and Linux XDP/eBPF.")

# Export baseline states.
bpath = Path(f"{prefix}_bmv2_before.json")
xpath = Path(f"{prefix}_xdp_before.json")
cmp = Path(f"{prefix}_before_comparison.json")

bstate = sync_state.export_state("bmv2", bpath, THRIFT)
xstate = sync_state.export_state("xdp", xpath, THRIFT)

report = sync_state.compare(bpath, xpath, cmp)
assert report["equivalent"], "Targets differ before the demo"

# Verify the existing controlled demonstration flow.
b = bm.read_slots([SLOT], THRIFT)[SLOT]
map_id = xd.find_map_info()["id"]
xraw = xd.read_raw_slot(map_id, SLOT)
x = xd.decode_current_record(SLOT, xraw)

assert b is not None and x is not None
assert b["key"] == KEY and x["key"] == KEY
assert b["st"] == x["st"] == 1
assert b["synced"] == 1 and xraw[15] == 1
assert (b["last"], b["pkts"], b["bytes"]) == (
    x["last"], x["pkts"], x["bytes"]
)

# Advance time by 1 ms, keeping the existing flow live.
ts = max(b["last"], x["last"]) + 1000
assert ts - b["last"] <= 30_000_000, (
    "Demo flow expired. Reseed a controlled demo flow first."
)

packet_id = (time.time_ns() & 0x3FFFFFFF) | 0x40000000


def send_ack(target, pkt_id):
    if target == "xdp":
        tx, peer, capture = "cs-xdp-host", "cs-xdp", "cs-xdp"
    else:
        tx, peer, capture = "cs-host", "cs-bmv2", "cs-host"

    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + b"\x01\x08\x00"
    )

    packet = (
        Ether(
            src=get_if_hwaddr(tx),
            dst=get_if_hwaddr(peer),
            type=0x88B5,
        )
        / Raw(shim)
        / IP(src=SRC, dst=DST)
        / TCP(
            sport=SPORT, dport=DPORT,
            flags="A", seq=pkt_id, ack=pkt_id + 1
        )
    )

    sniffer = AsyncSniffer(iface=capture, store=True)
    sniffer.start()
    time.sleep(0.25)
    sendp(packet, iface=tx, count=1, verbose=False)
    time.sleep(0.55)
    frames = sniffer.stop()

    flags = []
    for frame in frames:
        raw = bytes(frame)
        if (
            len(raw) >= 27
            and raw[12:14] == b"\x88\xb5"
            and raw[14:20] == ts.to_bytes(6, "big")
            and raw[20:24] == pkt_id.to_bytes(4, "big")
        ):
            flags.append(raw[24])

    print(
        f"{target.upper()} response flags:",
        [f"0x{f:02x}" for f in flags]
    )

    if not flags or flags[-1] != 0x05:
        raise RuntimeError(f"{target} did not allow the ACK")

    return flags[-1]


print(f"\nDemo flow slot: {SLOT}")
print("Flow: 10.99.0.1:49153 -> 10.99.0.2:443")
print("Sending an ACK through XDP...")
fx = send_ack("xdp", packet_id)

print("Sending the same logical ACK through BMv2...")
fb = send_ack("bmv2", packet_id + 1)

# Verify both target records.
b_after = bm.read_slots([SLOT], THRIFT)[SLOT]
xraw_after = xd.read_raw_slot(map_id, SLOT)
x_after = xd.decode_current_record(SLOT, xraw_after)

expected = (
    1,
    ts,
    b["pkts"] + 1,
    b["bytes"] + 40
)

for name, record in (("BMv2", b_after), ("XDP", x_after)):
    actual = (
        record["st"], record["last"],
        record["pkts"], record["bytes"]
    )
    assert actual == expected, f"{name} state mismatch: {actual}"

assert b_after["key"] == x_after["key"] == KEY
assert b_after["synced"] == 1
assert xraw_after[14] == 1 and xraw_after[15] == 1

print("\nBMv2 state:", b_after)
print("XDP state:", x_after)
print("LIVE_PACKET_DEMO = PASS")

# Export and compare every flow.
bpath = Path(f"{prefix}_bmv2_after.json")
xpath = Path(f"{prefix}_xdp_after.json")
cmp = Path(f"{prefix}_after_comparison.json")

bstate = sync_state.export_state("bmv2", bpath, THRIFT)
xstate = sync_state.export_state("xdp", xpath, THRIFT)
report = sync_state.compare(bpath, xpath, cmp)

assert report["equivalent"], "Full state equivalence failed"
assert len(bstate["records"]) == len(xstate["records"])

summary = {
    "created_utc": stamp,
    "demo_slot": SLOT,
    "demo_key": KEY,
    "timestamp_us": ts,
    "xdp_flags": fx,
    "bmv2_flags": fb,
    "bmv2_records": len(bstate["records"]),
    "xdp_records": len(xstate["records"]),
    "exact_matches": len(report["exact_matches"]),
    "conflicts": len(report["slot_conflicts"]),
    "equivalent": report["equivalent"],
    "demo_flow": {
        k: b_after[k]
        for k in ("slot", "key", "st", "last", "pkts", "bytes")
    }
}

summary_path = Path(f"{prefix}_summary.json")
summary_path.write_text(json.dumps(summary, indent=2) + "\n")

print("Total BMv2 records:", len(bstate["records"]))
print("Total XDP records:", len(xstate["records"]))
print("Exact matches:", len(report["exact_matches"]))
print("FULL_STATE_EQUIVALENCE = PASS")
print("Summary:", summary_path)
PY

section "4. BIDIRECTIONAL CHECKPOINT"

if (( APPLY )); then
    echo "Applying checkpoint. Traffic-quiesced acknowledgement supplied."
    sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
        scripts/sync_state.py \
        --direction bmv2-to-xdp --apply --traffic-quiesced

    sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
        scripts/sync_state.py \
        --direction xdp-to-bmv2 --apply --traffic-quiesced
else
    echo "Safe mode: dry-run only; no checkpoint writes."

    sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
        scripts/sync_state.py --direction bmv2-to-xdp

    sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
        scripts/sync_state.py --direction xdp-to-bmv2

    echo
    echo "For actual checkpoint writes, stop all traffic and run:"
    echo "bash scripts/crossstate_master_demo.sh --checkpoint-apply --traffic-quiesced"
fi

section "5. FINAL SUMMARY"

echo "Regression: PASS (unless skipped)"
echo "BMv2 live packet: PASS"
echo "XDP live packet: PASS"
echo "Full state comparison: PASS"
echo "Bidirectional checkpoint plans: PASS"
echo "Artifacts: artifacts/state/master_demo_*"
echo
git status -sb
echo
echo "CROSSSTATE_MASTER_DEMO = PASS"
