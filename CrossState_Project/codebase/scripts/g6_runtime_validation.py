#!/usr/bin/env python3
"""CrossState G6 runtime validation on BMv2 and XDP."""

import os
import subprocess
import sys
import time
from pathlib import Path

from scapy.all import (
    AsyncSniffer, Ether, IP, TCP, Raw,
    get_if_hwaddr, sendp
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import import_bmv2_state as bm
from scripts import import_xdp_state as xd
from scripts import sync_state

SLOT = 41751
KEY = [174260225, 49154, 174260226, 443, 6]
SRC = "10.99.0.1"
DST = "10.99.0.2"
SPORT = 49154
DPORT = 443
THRIFT = 9090
TIMEOUT = 30_000_000

STATE_DIR = ROOT / "artifacts" / "state"


def check_interfaces():
    import subprocess

    for iface in ("cs-host", "cs-bmv2", "cs-xdp-host", "cs-xdp"):
        subprocess.run(
            ["ip", "link", "show", "dev", iface],
            check=True,
            stdout=subprocess.DEVNULL,
        )

    subprocess.run(
        ["ss", "-lnt", "sport", "=", ":9090"],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def read_bmv2():
    return bm.read_slots([SLOT], THRIFT)[SLOT]


def read_xdp():
    map_id = xd.find_map_info()["id"]
    raw = xd.read_raw_slot(map_id, SLOT)
    return xd.decode_current_record(SLOT, raw), raw


def check_record(record, st, last, pkts, byte_count, target):
    assert record is not None, f"{target}: missing record"
    assert record["key"] == KEY, f"{target}: wrong key"
    assert record["st"] == st, f"{target}: state {record['st']}"
    assert record["last"] == last, f"{target}: timestamp mismatch"
    assert record["pkts"] == pkts, f"{target}: packet counter mismatch"
    assert record["bytes"] == byte_count, f"{target}: byte counter mismatch"


def logical(record):
    return tuple(record[k] for k in ("key", "st", "last", "pkts", "bytes"))


def send_packet(target, ts, pkt_id, tcp_flags, shadow=False):
    if target == "xdp":
        tx, peer, capture = "cs-xdp-host", "cs-xdp", "cs-xdp"
    elif target == "bmv2":
        tx, peer, capture = "cs-host", "cs-bmv2", "cs-host"
    else:
        raise ValueError(target)

    shim_flags = 0x01 | (0x02 if shadow else 0x00)

    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + bytes([shim_flags])
        + b"\x08\x00"
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
            sport=SPORT,
            dport=DPORT,
            flags=tcp_flags,
            seq=pkt_id & 0xFFFFFFFF,
            ack=(pkt_id + 1) & 0xFFFFFFFF,
        )
    )

    sniffer = AsyncSniffer(iface=capture, store=True)
    sniffer.start()
    time.sleep(0.25)
    sendp(packet, iface=tx, count=1, verbose=False)
    time.sleep(0.45)
    packets = sniffer.stop()

    observed = []
    for p in packets:
        raw = bytes(p)
        if (
            len(raw) >= 27
            and raw[12:14] == b"\x88\xb5"
            and raw[14:20] == ts.to_bytes(6, "big")
            and raw[20:24] == pkt_id.to_bytes(4, "big")
        ):
            observed.append(raw[24])

    if not observed:
        raise RuntimeError(
            f"{target}: no response captured for packet {pkt_id}"
        )

    result = observed[-1]
    print(
        f"{target}: packet={pkt_id} "
        f"flags={[f'0x{x:02x}' for x in observed]} "
        f"selected=0x{result:02x}"
    )
    return result


def run_checkpoint(direction):
    print(f"\n========== CHECKPOINT {direction} ==========")
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "sync_state.py"),
            "--direction", direction,
            "--apply",
            "--traffic-quiesced",
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        check=True,
    )


def assert_both(st, last, pkts, byte_count):
    b = read_bmv2()
    x, raw = read_xdp()

    check_record(b, st, last, pkts, byte_count, "BMv2")
    check_record(x, st, last, pkts, byte_count, "XDP")

    assert b["synced"] == 1, "BMv2 readiness is false"
    assert raw[14] == 1 and raw[15] == 1, "XDP readiness is false"

    assert logical(b) == logical(x), "Targets differ"
    return b, x


def main():
    print("=" * 68)
    print("CROSSSTATE G6 FINAL RUNTIME VALIDATION")
    print("=" * 68)

    check_interfaces()

    b = read_bmv2()
    x, xraw = read_xdp()

    assert b is not None and x is not None
    assert b["key"] == KEY and x["key"] == KEY
    assert b["last"] == x["last"] == 2_000_000_000
    assert b["pkts"] == x["pkts"] == 1
    assert b["bytes"] == x["bytes"] == 40
    assert b["synced"] == 1 and xraw[15] == 1

    print("\nG6 isolated flow:", SLOT)
    print("Other existing flows are not targeted.")

    # --------------------------------------------------------
    # A. Expiry and expired-flow rejection
    # --------------------------------------------------------
    print("\n========== A. IDLE EXPIRY ==========")

    expire_ts = b["last"] + TIMEOUT + 1
    reopen_ts = expire_ts + 1

    # An ACK after the timeout must be dropped without mutation.
    for target, pkt_id in (("xdp", 0xC7000001), ("bmv2", 0xC7000002)):
        flags = send_packet(target, expire_ts, pkt_id, "A")
        assert flags == 0x01, f"{target}: expired ACK not dropped"

    b_after_ack = read_bmv2()
    x_after_ack, _ = read_xdp()

    assert logical(b_after_ack) == logical(b)
    assert logical(x_after_ack) == logical(x)
    print("EXPIRED_ACK_DROP_BOTH_TARGETS = PASS")
    print("EXPIRED_FLOW_STATE_UNCHANGED = PASS")

    # A new SYN must reopen the expired slot as NEW.
    for target, pkt_id in (("xdp", 0xC7000003), ("bmv2", 0xC7000004)):
        flags = send_packet(target, reopen_ts, pkt_id, "S")
        assert flags == 0x05, f"{target}: expired flow did not reopen"

    b, x = read_bmv2(), read_xdp()[0]
    check_record(b, 1, reopen_ts, 1, 40, "BMv2")
    check_record(x, 1, reopen_ts, 1, 40, "XDP")
    assert b["synced"] == 0
    assert read_xdp()[1][15] == 0

    print("EXPIRED_FLOW_REOPEN_BOTH_TARGETS = PASS")

    run_checkpoint("bmv2-to-xdp")
    run_checkpoint("xdp-to-bmv2")

    # --------------------------------------------------------
    # B. Shadow mode fail-closed and synchronized processing
    # --------------------------------------------------------
    print("\n========== B. SHADOW GATE ==========")

    sync_state.set_xdp_ready([SLOT], False)
    sync_state.set_bmv2_ready([SLOT], False, THRIFT)

    before_b = read_bmv2()
    before_x = read_xdp()[0]

    shadow_ts = reopen_ts + 1

    for target, pkt_id in (("xdp", 0xC7000011), ("bmv2", 0xC7000012)):
        flags = send_packet(
            target, shadow_ts, pkt_id, "A", shadow=True
        )
        assert flags == 0x0B, (
            f"{target}: unsynchronized shadow flow not skipped"
        )

    after_b = read_bmv2()
    after_x, after_xraw = read_xdp()

    assert logical(after_b) == logical(before_b)
    assert logical(after_x) == logical(before_x)
    assert after_b["synced"] == 0
    assert after_xraw[15] == 0

    print("UNSYNCED_SHADOW_SKIP_BOTH_TARGETS = PASS")
    print("UNSYNCED_SHADOW_NO_MUTATION = PASS")

    # Mark both replicas ready and test shadow processing.
    sync_state.set_xdp_ready([SLOT], True)
    sync_state.set_bmv2_ready([SLOT], True, THRIFT)

    shadow_ready_ts = shadow_ts + 1

    for target, pkt_id in (("xdp", 0xC7000013), ("bmv2", 0xC7000014)):
        flags = send_packet(
            target, shadow_ready_ts, pkt_id, "A", shadow=True
        )
        assert flags == 0x07, (
            f"{target}: synchronized shadow flow not allowed"
        )

    b, x = read_bmv2(), read_xdp()[0]
    check_record(b, 1, shadow_ready_ts, 2, 80, "BMv2")
    check_record(x, 1, shadow_ready_ts, 2, 80, "XDP")
    assert logical(b) == logical(x)

    print("SYNCED_SHADOW_ALLOW_BOTH_TARGETS = PASS")

    # --------------------------------------------------------
    # C. Runtime fail-closed readiness and recovery
    # --------------------------------------------------------
    print("\n========== C. FAIL-CLOSED RECOVERY ==========")

    sync_state.fail_closed("xdp", [SLOT], THRIFT)
    sync_state.fail_closed("bmv2", [SLOT], THRIFT)

    b_unready = read_bmv2()
    x_unready, x_unready_raw = read_xdp()

    assert b_unready["synced"] == 0
    assert x_unready_raw[15] == 0

    print("RUNTIME_FAIL_CLOSED_MARKERS = PASS")

    run_checkpoint("bmv2-to-xdp")
    run_checkpoint("xdp-to-bmv2")

    assert_both(1, shadow_ready_ts, 2, 80)
    print("FAIL_CLOSED_CHECKPOINT_RECOVERY = PASS")

    # --------------------------------------------------------
    # D. TCP termination and closed-flow enforcement
    # --------------------------------------------------------
    print("\n========== D. CLOSED-STATE ENFORCEMENT ==========")

    rst_ts = shadow_ready_ts + 1

    for target, pkt_id in (("xdp", 0xC7000021), ("bmv2", 0xC7000022)):
        flags = send_packet(target, rst_ts, pkt_id, "R")
        assert flags == 0x05, f"{target}: RST was not allowed"

    b, x = read_bmv2(), read_xdp()[0]
    check_record(b, 3, rst_ts, 3, 120, "BMv2")
    check_record(x, 3, rst_ts, 3, 120, "XDP")
    assert logical(b) == logical(x)

    # A subsequent ACK on CLOSED must be dropped.
    closed_ack_ts = rst_ts + 1

    for target, pkt_id in (("xdp", 0xC7000023), ("bmv2", 0xC7000024)):
        flags = send_packet(target, closed_ack_ts, pkt_id, "A")
        assert flags == 0x01, f"{target}: CLOSED ACK was not dropped"

    b_after_closed = read_bmv2()
    x_after_closed = read_xdp()[0]

    check_record(b_after_closed, 3, rst_ts, 3, 120, "BMv2")
    check_record(x_after_closed, 3, rst_ts, 3, 120, "XDP")
    assert logical(b_after_closed) == logical(x_after_closed)

    print("RST_CLOSED_TRANSITION_BOTH_TARGETS = PASS")
    print("CLOSED_FLOW_PACKET_DROP_BOTH_TARGETS = PASS")

    # --------------------------------------------------------
    # E. Final checkpoint and all-record equivalence
    # --------------------------------------------------------
    print("\n========== E. FINAL STATE RECONCILIATION ==========")

    run_checkpoint("bmv2-to-xdp")
    run_checkpoint("xdp-to-bmv2")

    bpath = STATE_DIR / "g6_final_bmv2.json"
    xpath = STATE_DIR / "g6_final_xdp.json"
    report = STATE_DIR / "g6_final_comparison.json"

    bs = sync_state.export_state("bmv2", bpath, THRIFT)
    xs = sync_state.export_state("xdp", xpath, THRIFT)

    result = sync_state.compare(bpath, xpath, report)

    assert len(bs["records"]) == 86
    assert len(xs["records"]) == 86
    assert result.get("equivalent") is True
    assert len(result.get("slot_conflicts", [])) == 0
    assert not result.get("left_only_slots")
    assert not result.get("right_only_slots")

    slots = sorted(r["slot"] for r in bs["records"])
    bm_states = bm.read_slots(slots, THRIFT)
    map_id = xd.find_map_info()["id"]

    for slot in slots:
        assert bm_states[slot] is not None
        assert bm_states[slot]["synced"] == 1

        raw = xd.read_raw_slot(map_id, slot)
        assert raw[14] == 1 and raw[15] == 1

    print("BMv2 final records:", len(bs["records"]))
    print("XDP final records:", len(xs["records"]))
    print("Exact equivalence:", result["equivalent"])
    print("All 86 BMv2 markers ready: PASS")
    print("All 86 XDP markers ready: PASS")

    print("\n" + "=" * 68)
    print("G6_RUNTIME_VALIDATION = PASS")
    print("=" * 68)


if __name__ == "__main__":
    main()
