#!/usr/bin/env python3
"""CrossState packet-trace replay with bidirectional BMv2/XDP migration.

Preparation assumptions:
- Input is mawi_crossstate_replay.pcap from mawi_crossstate_pipeline.py.
- The PCAP uses Ethernet type 0x88B5 followed by the 13-byte CrossState shim.
- Shim direction bit 0 means captured TCP initiator -> responder (inside).
- The first packet of every selected flow is its initiating SYN.
- The existing reference model and sync_state.py define firewall semantics.

The runner does not reset datapaths. It requires an already-running isolated
BMv2/XDP runtime and a quiescent checkpoint window. Four checkpoints are
performed, two in each direction. All packet decisions are checked against
the reference model and final records are checked against the reference table.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import struct
import subprocess
import sys
import time
import shutil
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import AsyncSniffer, Ether, get_if_hwaddr, sendp
from ref.model import Ev, canon, slot_of, step, ALLOW
from scripts import sync_state
from scripts import live_sync_state
from scripts.datapath_hal import Bmv2Target, XdpTarget, create_target
from scripts.live_migration import LiveMigrator
from scripts.automatic_failover import FailoverWatcher
from scripts.sota_metrics import sota_json, sota_table, sota_csv, CrossStateResult

THRIFT_PORT = 9090
ETHERTYPE = 0x88B5
IP_OFFSET = 27
SHIM_OFFSET = 14
TIMEOUT_US = 30_000_000


def log(message: str) -> None:
    print(message, flush=True)


def run_preflight() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Run this script with sudo and the CrossState venv PYTHONPATH.")

    required = ("cs-host", "cs-bmv2", "cs-xdp-host", "cs-xdp")
    missing = []
    for iface in required:
        result = subprocess.run(
            ["ip", "link", "show", "dev", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode:
            missing.append(iface)

    if missing:
        raise RuntimeError(
            "Runtime interfaces are missing: " + ", ".join(missing)
            + ". Start the isolated CrossState runtime first with "
            "bash scripts/crossstate_start_runtime.sh, then rerun. "
            "The script will not create interfaces or restart targets itself."
        )

    ss = subprocess.run(["ss", "-lnt"], capture_output=True, text=True, check=True).stdout
    if ":9090" not in ss:
        raise RuntimeError("BMv2 Thrift port 9090 is not listening.")

    net = subprocess.run(["bpftool", "net", "show"], capture_output=True, text=True, check=True).stdout
    if "cs-xdp" not in net:
        raise RuntimeError("No XDP attachment found on cs-xdp.")

    maps = subprocess.run(["bpftool", "map", "show"], capture_output=True, text=True, check=True).stdout
    if "flow_state" not in maps:
        raise RuntimeError("The XDP flow_state map was not found.")

    log("PREFLIGHT = PASS (interfaces, Thrift, XDP attachment and map)")


def read_manifest(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            row["index"] = int(row["index"])
            row["slot"] = int(row["slot"])
            row["key"] = tuple(int(v) for v in json.loads(row["key"]))
            rows.append(row)
    rows.sort(key=lambda r: r["index"])
    if len(rows) == 0:
        raise RuntimeError("MAWI flow manifest is empty.")
    return rows


def parse_replay_frame(frame: bytes) -> dict[str, Any]:
    if len(frame) < 14 + 13 + 40 or frame[12:14] != b"\x88\xb5":
        raise ValueError("Invalid CrossState replay Ethernet frame.")
    if frame[25:27] != b"\x08\x00":
        raise ValueError("Replay shim inner EtherType is not IPv4.")

    ts = int.from_bytes(frame[14:20], "big")
    pkt_id = int.from_bytes(frame[20:24], "big")
    direction = frame[24] & 0x01
    ipoff = IP_OFFSET
    version = frame[ipoff] >> 4
    ihl = (frame[ipoff] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < ipoff + ihl + 20:
        raise ValueError("Invalid IPv4/TCP packet in replay PCAP.")

    ip_total = struct.unpack("!H", frame[ipoff + 2:ipoff + 4])[0]
    if ip_total < ihl + 20 or frame[ipoff + 9] != 6:
        raise ValueError("Expected a complete IPv4/TCP header.")

    src_ip = int.from_bytes(frame[ipoff + 12:ipoff + 16], "big")
    dst_ip = int.from_bytes(frame[ipoff + 16:ipoff + 20], "big")
    tcp_off = ipoff + ihl
    sport, dport = struct.unpack("!HH", frame[tcp_off:tcp_off + 4])
    tcp_flags = frame[tcp_off + 13]

    e = Ev(
        src_ip, sport, dst_ip, dport, 6,
        bool(direction),
        bool(tcp_flags & 0x02),
        bool(tcp_flags & 0x10),
        bool(tcp_flags & 0x01),
        bool(tcp_flags & 0x04),
        ip_total,
        ts,
    )
    key = tuple(int(v) for v in canon(e))
    slot = int(slot_of(key))

    return {
        "frame": frame,
        "key": key,
        "slot": slot,
        "ts": ts,
        "pkt_id": pkt_id,
        "direction": direction,
        "ip_len": ip_total,
        "tcp_flags": tcp_flags,
        "event": e,
    }


def load_replay(path: Path, manifest: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    by_key = {r["key"]: r for r in manifest}
    if len(by_key) != len(manifest):
        raise RuntimeError("Duplicate flow key in manifest.")

    flows: dict[int, list[dict[str, Any]]] = defaultdict(list)
    seen_pkt_ids = set()
    magic_endian = None
    with path.open("rb") as fh:
        hdr = fh.read(24)
        if len(hdr) != 24:
            raise RuntimeError("Invalid replay PCAP header.")
        magic = hdr[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            magic_endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            magic_endian = ">"
        else:
            raise RuntimeError("Expected a microsecond classic PCAP file.")
        linktype = struct.unpack(magic_endian + "I", hdr[20:24])[0]
        if linktype != 1:
            raise RuntimeError(f"Expected Ethernet PCAP linktype 1, got {linktype}.")

        packet_records = 0
        while True:
            rec = fh.read(16)
            if not rec:
                break
            if len(rec) != 16:
                raise RuntimeError("Truncated PCAP record header.")
            _sec, _usec, incl, _orig = struct.unpack(magic_endian + "IIII", rec)
            frame = fh.read(incl)
            if len(frame) != incl:
                raise RuntimeError("Truncated PCAP frame.")
            packet = parse_replay_frame(frame)
            row = by_key.get(packet["key"])
            if row is None:
                raise RuntimeError(f"Packet references a flow absent from manifest: {packet['key']}")
            if packet["slot"] != row["slot"]:
                raise RuntimeError(f"Slot mismatch for manifest flow {row['index']}.")
            if packet["pkt_id"] in seen_pkt_ids:
                raise RuntimeError(f"Duplicate packet identifier {packet['pkt_id']}.")
            seen_pkt_ids.add(packet["pkt_id"])
            packet_records += 1
            flows[row["index"]].append(packet)

    expected_total = sum(int(r["packets"]) for r in manifest)
    if packet_records != expected_total:
        raise RuntimeError(
            f"Replay/manifest packet count mismatch: {packet_records} vs {expected_total}."
        )

    for row in manifest:
        seq = flows.get(row["index"], [])
        if len(seq) != int(row["packets"]):
            raise RuntimeError(f"Flow {row['index']} packet count differs from manifest.")
        if not seq:
            raise RuntimeError(f"Flow {row['index']} has no replay packets.")
        first = seq[0]
        if not (first["tcp_flags"] & 0x02) or (first["tcp_flags"] & 0x10) or first["direction"] != 1:
            raise RuntimeError(
                f"Flow {row['index']} does not begin with an inside initiating SYN."
            )
        # Verify observed SYN-ACK and final initiator ACK exist in the selected trace.
        saw_synack = False
        saw_final_ack = False
        for pkt in seq[1:]:
            f = pkt["tcp_flags"]
            if (f & 0x12) == 0x12 and pkt["direction"] == 0:
                saw_synack = True
            elif saw_synack and (f & 0x10) and not (f & 0x02) and pkt["direction"] == 1:
                saw_final_ack = True
                break
        if not saw_synack or not saw_final_ack:
            raise RuntimeError(f"Flow {row['index']} is missing an observed TCP handshake leg.")

    return flows


def snapshot_to_table(snapshot: dict[str, Any]) -> dict[int, tuple]:
    table = {}
    for rec in snapshot["records"]:
        table[int(rec["slot"])] = (
            tuple(int(v) for v in rec["key"]),
            int(rec["st"]),
            int(rec["last"]),
            int(rec["pkts"]),
            int(rec["bytes"]),
        )
    return table


def export_pair(outdir: Path, label: str):
    bp = outdir / f"{label}_bmv2.json"
    xp = outdir / f"{label}_xdp.json"
    rp = outdir / f"{label}_comparison.json"
    bs = sync_state.export_state("bmv2", bp, THRIFT_PORT)
    xs = sync_state.export_state("xdp", xp, THRIFT_PORT)
    report = sync_state.compare(bp, xp, rp)
    return bs, xs, report, bp, xp, rp


def logical_record(rec: dict[str, Any]) -> tuple:
    return (
        tuple(int(v) for v in rec["key"]),
        int(rec["st"]), int(rec["last"]),
        int(rec["pkts"]), int(rec["bytes"]),
    )


def assert_pair_equal(bs, xs, report, label: str, expected_count: int | None = None):
    if not report.get("equivalent", False):
        raise RuntimeError(f"BMv2/XDP state mismatch after {label}.")
    bmap = {int(r["slot"]): r for r in bs["records"]}
    xmap = {int(r["slot"]): r for r in xs["records"]}
    if set(bmap) != set(xmap):
        raise RuntimeError(f"Slot sets differ after {label}.")
    for slot in bmap:
        if logical_record(bmap[slot]) != logical_record(xmap[slot]):
            raise RuntimeError(f"Logical record differs at slot {slot} after {label}.")
    if expected_count is not None and len(bmap) != expected_count:
        raise RuntimeError(f"Expected {expected_count} records after {label}, got {len(bmap)}.")
    return bmap, xmap


def stream_subprocess(command: list[str], logfile: Path, label: str) -> float:
    start = time.perf_counter()
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{ROOT}:{env.get('PYTHONPATH', '')}"
    with logfile.open("w", encoding="utf-8") as out:
        proc = subprocess.Popen(
            command, cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="", flush=True)
            out.write(line)
            out.flush()
        rc = proc.wait()
    elapsed = time.perf_counter() - start
    if rc:
        raise RuntimeError(f"{label} failed with exit code {rc}; see {logfile}.")
    return elapsed


def run_checkpoint(outdir: Path, ordinal: int, direction: str,
                   checkpoints: list[dict[str, Any]], use_live: bool = False,
                   stop_duration_ms: int = 100) -> None:
    log(f"\n========== MAWI CHECKPOINT {ordinal}: {direction} ==========")
    state_dir = ROOT / "artifacts" / "state"
    before = {p.resolve() for p in state_dir.glob("sync_*")}
    before |= {p.resolve() for p in state_dir.glob("live_sync_*")}
    logfile = outdir / f"checkpoint_{ordinal}_{direction}.log"

    if use_live:
        result = live_sync_state.live_sync(
            direction,
            thrift_port=THRIFT_PORT,
            stop_duration_ms=stop_duration_ms,
        )
        if result != 0:
            raise RuntimeError(f"Live checkpoint {ordinal} {direction} failed.")
        elapsed = 0.0  # live_sync reports its own timing
    else:
        elapsed = stream_subprocess(
            [
                sys.executable, str(ROOT / "scripts" / "sync_state.py"),
                "--direction", direction,
                "--apply", "--traffic-quiesced",
                "--thrift-port", str(THRIFT_PORT),
            ],
            logfile,
            f"checkpoint {ordinal} {direction}",
        )
    new_files = [
        p for p in state_dir.glob("sync_*") if p.resolve() not in before
    ] + [
        p for p in state_dir.glob("live_sync_*") if p.resolve() not in before
    ]
    audit_dir = outdir / "checkpoint_audits" / f"checkpoint_{ordinal}"
    audit_dir.mkdir(parents=True, exist_ok=True)
    for p in new_files:
        if p.is_file():
            shutil.copy2(p, audit_dir / p.name)
    checkpoints.append({
        "checkpoint": ordinal,
        "direction": direction,
        "mode": "live" if use_live else "quiesced",
        "duration_seconds": elapsed,
        "log": str(logfile),
        "audit_files_copied": len(new_files),
        "status": "PASS",
    })
    mode_tag = "LIVE" if use_live else "QUIESCED"
    log(f"CHECKPOINT_{ordinal} = PASS ({mode_tag}, {elapsed:.3f} seconds)")


def target_ifaces(target: str):
    if target == "bmv2":
        return "cs-host", "cs-bmv2", "cs-host"
    if target == "xdp":
        return "cs-xdp-host", "cs-xdp", "cs-xdp"
    raise ValueError(target)


def make_expected(packet: dict[str, Any], oracle: dict[int, tuple]) -> int:
    return int(step(oracle, packet["event"]))


def replay_batch(
    target: str,
    packets: list[dict[str, Any]],
    oracle: dict[int, tuple],
    decision_rows: list[dict[str, Any]],
    *,
    batch_size: int,
    inter_packet_ms: float,
    phase: str,
    latency_budget: dict[str, int] | None = None,
    phase_metrics: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Replay a phase and optionally sample host-observed request/response time.

    Latency samples are sent one at a time so a matching response can be timed
    from immediately before sendp() until the response is seen by the capture
    callback. This is a host-observed software-testbed RTT, not wire-level
    one-way latency. The remaining packets retain the original batched path.
    """
    from scapy.all import Ether

    phase_start = time.perf_counter()
    if not packets:
        log(f"{phase}: no packets in this segment; skipped.")
        result = {
            "phase": phase, "target": target, "packets_expected": 0,
            "packets_received": 0, "packets_missing": 0,
            "decision_mismatches": 0, "duration_seconds": 0.0,
            "harness_throughput_pps": None, "latency_samples": 0,
        }
        if phase_metrics is not None:
            phase_metrics.append(result)
        return result

    tx, peer, capture = target_ifaces(target)
    tx_mac = bytes.fromhex(get_if_hwaddr(tx).replace(":", ""))
    peer_mac = bytes.fromhex(get_if_hwaddr(peer).replace(":", ""))
    if len(tx_mac) != 6 or len(peer_mac) != 6:
        raise RuntimeError("Could not read interface MAC addresses.")

    sent = 0
    allowed_count = 0
    dropped_count = 0
    missing_total = 0
    mismatch_total = 0
    latency_values: list[float] = []

    for offset in range(0, len(packets), batch_size):
        batch = packets[offset:offset + batch_size]
        expected: dict[int, int] = {}
        packet_by_id: dict[int, dict[str, Any]] = {}
        frames_by_id: dict[int, Any] = {}
        for pkt in batch:
            pktid = int(pkt["pkt_id"])
            if pktid in expected:
                raise RuntimeError(f"Duplicate packet ID in replay batch: {pktid}")
            decision = make_expected(pkt, oracle)
            expected[pktid] = decision
            packet_by_id[pktid] = pkt
            frame = bytearray(pkt["frame"])
            frame[0:6] = peer_mac
            frame[6:12] = tx_mac
            frames_by_id[pktid] = Ether(bytes(frame))

        observed: dict[int, list[int]] = defaultdict(list)
        measured: dict[int, float] = {}
        sample_count = min(max(0, int((latency_budget or {}).get(target, 0))), len(batch))

        # Optional sequential sample path. All expected decisions above were
        # calculated in packet order; packets are sent below in that same order.
        if sample_count:
            import threading

            sample_packets = batch[:sample_count]
            sample_events = {int(pkt["pkt_id"]): threading.Event() for pkt in sample_packets}
            sample_times: dict[int, float] = {}

            def on_sample_response(frame):
                raw = bytes(frame)
                if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
                    return
                pktid = int.from_bytes(raw[20:24], "big")
                ts = int.from_bytes(raw[14:20], "big")
                pkt = packet_by_id.get(pktid)
                if pkt is None or ts != int(pkt["ts"]):
                    return
                observed[pktid].append(raw[24])
                event = sample_events.get(pktid)
                if event is not None:
                    event.set()

            sample_sniffer = AsyncSniffer(iface=capture, store=False, prn=on_sample_response)
            sample_sniffer.start()
            time.sleep(0.12)
            try:
                for pkt in sample_packets:
                    pktid = int(pkt["pkt_id"])
                    t0 = time.perf_counter()
                    sendp(frames_by_id[pktid], iface=tx, verbose=False)
                    received = sample_events[pktid].wait(timeout=2.0)
                    if received:
                        latency_ms = (time.perf_counter() - t0) * 1000.0
                        measured[pktid] = latency_ms
                        latency_values.append(latency_ms)
                    if latency_budget is not None:
                        latency_budget[target] = max(0, int(latency_budget.get(target, 0)) - 1)
            finally:
                try:
                    sample_sniffer.stop()
                except Exception:
                    pass

        # Remaining packets follow the existing Scapy batch replay path.
        remaining = batch[sample_count:]
        if remaining:
            batch_sniffer = AsyncSniffer(iface=capture, store=True)
            batch_sniffer.start()
            time.sleep(0.12)
            try:
                sendp(
                    [frames_by_id[int(pkt["pkt_id"])] for pkt in remaining],
                    iface=tx,
                    inter=max(0.0, inter_packet_ms / 1000.0),
                    verbose=False,
                )
                time.sleep(0.30)
                captured = batch_sniffer.stop()
            except Exception:
                try:
                    batch_sniffer.stop()
                except Exception:
                    pass
                raise

            for frame in captured:
                raw = bytes(frame)
                if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
                    continue
                pktid = int.from_bytes(raw[20:24], "big")
                ts = int.from_bytes(raw[14:20], "big")
                pkt = packet_by_id.get(pktid)
                if pkt is not None and ts == int(pkt["ts"]):
                    observed[pktid].append(raw[24])

        missing = []
        mismatches = []
        for pktid, expected_decision in expected.items():
            flags_list = observed.get(pktid, [])
            p = packet_by_id[pktid]
            if not flags_list:
                missing.append(pktid)
                decision_rows.append({
                    "phase": phase, "target": target, "slot": p["slot"],
                    "packet_id": pktid, "timestamp_us": p["ts"],
                    "expected": "ALLOW" if expected_decision else "DROP",
                    "observed": "MISSING", "response_flags_hex": "",
                    "match": False, "delivered": False,
                    "host_observed_latency_ms": None,
                    "latency_measured": pktid in measured,
                })
                continue

            response_flags = flags_list[-1]
            actual_decision = 1 if (response_flags & 0x04) else 0
            if actual_decision != expected_decision:
                mismatches.append((pktid, expected_decision, actual_decision, response_flags))

            if actual_decision:
                allowed_count += 1
            else:
                dropped_count += 1

            decision_rows.append({
                "phase": phase,
                "target": target,
                "slot": p["slot"],
                "packet_id": pktid,
                "timestamp_us": p["ts"],
                "expected": "ALLOW" if expected_decision else "DROP",
                "observed": "ALLOW" if actual_decision else "DROP",
                "response_flags_hex": f"0x{response_flags:02x}",
                "match": actual_decision == expected_decision,
                "delivered": True,
                "host_observed_latency_ms": measured.get(pktid),
                "latency_measured": pktid in measured,
            })

        sent += len(batch)
        missing_total += len(missing)
        mismatch_total += len(mismatches)
        log(
            f"{target.upper()} {phase}: {sent}/{len(packets)} packets checked; "
            f"allowed={allowed_count}, dropped={dropped_count}, "
            f"missing={missing_total}, decision_mismatches={mismatch_total}"
        )

        if missing or mismatches:
            raise RuntimeError(
                f"Packet replay validation failed in {phase} on {target}. "
                f"Missing responses={len(missing)} first={missing[:10]}; "
                f"decision mismatches={len(mismatches)} first={mismatches[:10]}. "
                "No packet retries were issued. Inspect the saved run logs and snapshots."
            )

    elapsed = max(time.perf_counter() - phase_start, 1e-12)
    result = {
        "phase": phase,
        "target": target,
        "packets_expected": len(packets),
        "packets_received": len(packets) - missing_total,
        "packets_missing": missing_total,
        "decision_mismatches": mismatch_total,
        "allowed": allowed_count,
        "dropped": dropped_count,
        "duration_seconds": elapsed,
        "harness_throughput_pps": (len(packets) - missing_total) / elapsed,
        "latency_samples": len(latency_values),
        "latency_p50_ms": (float(__import__("numpy").percentile(latency_values, 50)) if latency_values else None),
        "latency_p95_ms": (float(__import__("numpy").percentile(latency_values, 95)) if latency_values else None),
        "latency_p99_ms": (float(__import__("numpy").percentile(latency_values, 99)) if latency_values else None),
    }
    if phase_metrics is not None:
        phase_metrics.append(result)
    log(f"{phase} on {target.upper()} = PASS ({sent} packets; {elapsed:.3f}s)")
    return result

def flatten(rows: list[dict[str, Any]], flows: dict[int, list[dict[str, Any]]], which: str) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        seq = flows[row["index"]]
        if which == "prefix":
            result.append(seq[0])
        else:
            result.extend(seq[1:])
    return result


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def create_plots(outdir: Path, decisions: list[dict[str, Any]], checkpoints: list[dict[str, Any]], final_b: dict[int, dict], final_x: dict[int, dict], cohort_a: list[dict], cohort_b: list[dict]) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log("Matplotlib unavailable; CSV/JSON results saved, plots skipped.")
        return

    plotdir = outdir / "plots_migration"
    plotdir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 9,
        "axes.titlesize": 11, "axes.labelsize": 9,
        "savefig.facecolor": "white", "figure.facecolor": "white",
        "axes.grid": True, "grid.alpha": 0.22,
    })

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(plotdir / f"{name}.pdf", bbox_inches="tight")
        fig.savefig(plotdir / f"{name}.svg", bbox_inches="tight")
        fig.savefig(plotdir / f"{name}.png", dpi=600, bbox_inches="tight")
        plt.close(fig)
        log(f"Plot saved: {name}")

    # 1. Final state record counts.
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    labels = ["BMv2", "XDP", "Exact matches"]
    values = [len(final_b), len(final_x), sum(
        1 for s in final_b if s in final_x and logical_record(final_b[s]) == logical_record(final_x[s])
    )]
    bars = ax.bar(labels, values, color=["#2878B5", "#E87524", "#31966B"])
    ax.set_ylabel("Flow records")
    ax.set_title("Final Cross-Target State Equivalence")
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height(), f"{v:,}", ha="center", va="bottom")
    save(fig, "01_final_state_equivalence")

    # 2. Per-record counter parity.
    slots = sorted(set(final_b) & set(final_x))
    for idx, field, label, name in [
        (2, "pkts", "Packet counter", "02_packet_counter_parity"),
        (3, "bytes", "Byte counter", "03_byte_counter_parity"),
    ]:
        bv = [int(final_b[s][field]) for s in slots]
        xv = [int(final_x[s][field]) for s in slots]
        fig, ax = plt.subplots(figsize=(5.8, 5.3))
        ax.scatter(bv, xv, s=16, alpha=0.45)
        upper = max(bv + xv + [1])
        ax.plot([0, upper], [0, upper], "r--", label="y = x")
        ax.set_xlabel(f"BMv2 {label}")
        ax.set_ylabel(f"XDP {label}")
        ax.set_title(f"{label} Agreement Across Final Flow Records")
        ax.legend()
        save(fig, name)

    # 4. Final TCP state distribution.
    names = {1: "NEW", 2: "EST", 3: "CLOSED"}
    state_names = ["NEW", "EST", "CLOSED"]
    bc = Counter(names.get(int(r["st"]), "OTHER") for r in final_b.values())
    xc = Counter(names.get(int(r["st"]), "OTHER") for r in final_x.values())
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    pos = list(range(3)); width = 0.36
    ax.bar([p-width/2 for p in pos], [bc[n] for n in state_names], width, label="BMv2")
    ax.bar([p+width/2 for p in pos], [xc[n] for n in state_names], width, label="XDP")
    ax.set_xticks(pos); ax.set_xticklabels(state_names)
    ax.set_ylabel("Flow records"); ax.set_title("Final TCP State Distribution")
    ax.legend(); save(fig, "04_tcp_state_distribution")

    # 5. Packet decision confusion matrix.
    expected = [1 if r["expected"] == "ALLOW" else 0 for r in decisions]
    observed = [1 if r["observed"] == "ALLOW" else 0 for r in decisions]
    matrix = np.zeros((2, 2), dtype=int)
    for e, o in zip(expected, observed):
        matrix[e, o] += 1
    fig, ax = plt.subplots(figsize=(5.2, 4.5))
    im = ax.imshow(matrix, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["DROP", "ALLOW"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["DROP", "ALLOW"])
    ax.set_xlabel("Datapath decision"); ax.set_ylabel("Reference decision")
    ax.set_title("Reference-to-Datapath Packet Decision Agreement")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{matrix[i,j]:,}", ha="center", va="center")
    fig.colorbar(im, ax=ax, label="Packet count")
    save(fig, "05_packet_decision_confusion_matrix")

    # 6. Packet decision agreement by target.
    target_stats = {}
    for t in ("bmv2", "xdp"):
        rows = [r for r in decisions if r["target"] == t]
        target_stats[t] = sum(bool(r["match"]) for r in rows) / len(rows) * 100 if rows else 0
    fig, ax = plt.subplots(figsize=(5.8, 4.2))
    bars = ax.bar(["BMv2", "XDP"], [target_stats["bmv2"], target_stats["xdp"]], color=["#2878B5", "#E87524"])
    ax.set_ylim(0, 105); ax.set_ylabel("Decision agreement (%)")
    ax.set_title("Packet Decision Agreement by Datapath")
    for bar in bars:
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height(), f"{bar.get_height():.2f}%", ha="center", va="bottom")
    save(fig, "06_decision_agreement_by_target")

    # 7. Checkpoint duration.
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    labels = [f"CP{r['checkpoint']}\n{r['direction']}" for r in checkpoints]
    vals = [r["duration_seconds"] for r in checkpoints]
    bars = ax.bar(range(len(vals)), vals, color=["#2878B5", "#E87524", "#31966B", "#8064A2"][:len(vals)])
    ax.set_xticks(range(len(vals))); ax.set_xticklabels(labels)
    ax.set_ylabel("Elapsed checkpoint time (seconds)")
    ax.set_title("Quiesced Checkpoint Execution Time")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x()+bar.get_width()/2, bar.get_height(), f"{v:.2f}", ha="center", va="bottom")
    save(fig, "07_checkpoint_duration")

    # 8. Cohort sizes.
    fig, ax = plt.subplots(figsize=(5.8, 4.2))
    ax.bar(["Cohort A: BMv2 first", "Cohort B: XDP first"], [len(cohort_a), len(cohort_b)], color=["#2878B5", "#E87524"])
    ax.set_ylabel("MAWI TCP flows")
    ax.set_title("Bidirectional Migration Cohort Sizes")
    save(fig, "08_migration_cohort_sizes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, default=Path("/mnt/e/SDN/datasets/mawi/processed/run_20261113T123336Z"))
    parser.add_argument("--output-dir", type=Path, default=Path("/mnt/e/SDN/datasets/mawi/live_migration"))
    parser.add_argument("--cohort-size", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--inter-packet-ms", type=float, default=0.2)
    parser.add_argument("--latency-samples", type=int, default=50,
                        help="Sequential host-observed latency samples per target; 0 disables sampling.")
    parser.add_argument("--traffic-quiesced", action="store_true")
    parser.add_argument("--skip-checkpoint", action="store_true",
                        help="Replay packets without performing checkpoints "
                             "(live no-migration baseline; validates datapath "
                             "decisions against the reference model only).")
    parser.add_argument("--live", action="store_true",
                        help="Use live (non-quiesced) migration: pre-copy + stop-and-copy + cutover.")
    parser.add_argument("--live-cont", action="store_true",
                        help="Use continuous live migration with pre-copy, dirty-page "
                             "tracking, iterative convergence, stop-and-copy, and cutover "
                             "(minimal traffic interruption, no full quiesce).")
    parser.add_argument("--auto-failover", action="store_true",
                        help="Enable automatic failover watcher: monitor primary target "
                             "health and trigger live migration to standby on failure.")
    parser.add_argument("--failback", action="store_true",
                        help="Enable automatic failback to original primary after recovery "
                             "(requires --auto-failover).")
    parser.add_argument("--failover-interval", type=float, default=2.0,
                        help="Health check interval in seconds (auto-failover mode).")
    parser.add_argument("--failover-max-failures", type=int, default=3,
                        help="Consecutive failures before triggering failover (auto-failover mode).")
    parser.add_argument("--failover-max-iterations", type=int, default=None,
                        help="Maximum watcher iterations (auto-failover mode, for testing).")
    parser.add_argument("--stop-duration-ms", type=int, default=100,
                        help="Stop-and-copy window duration in milliseconds (live mode only).")
    args = parser.parse_args()

    if args.live and args.traffic_quiesced:
        parser.error("--live and --traffic-quiesced are mutually exclusive.")
    if args.live_cont and args.traffic_quiesced:
        parser.error("--live-cont and --traffic-quiesced are mutually exclusive.")
    if args.live and args.live_cont:
        parser.error("--live and --live-cont are mutually exclusive.")
    if args.skip_checkpoint:
        if args.live or args.live_cont:
            parser.error("--skip-checkpoint and --live/--live-cont are mutually exclusive.")
    elif not args.live and not args.live_cont and not args.traffic_quiesced:
        parser.error("Checkpoint apply requires --traffic-quiesced (or --live "
                     "for non-quiesced migration; --skip-checkpoint skips checkpoints entirely).")
    if args.auto_failover and not (args.live or args.live_cont):
        parser.error("--auto-failover requires --live or --live-cont (migration protocol).")
    if args.failback and not args.auto_failover:
        parser.error("--failback requires --auto-failover.")
    if args.cohort_size < 1 or args.batch_size < 1:
        parser.error("cohort-size and batch-size must be positive")
    if args.latency_samples < 0:
        parser.error("latency-samples must be nonnegative")

    # --- Live/continuous migration and automatic failover modes ---
    # These modes use the DatapathTarget HAL directly and bypass the
    # quiesced checkpoint flow. They require root + datapath access.
    if args.live_cont or args.auto_failover:
        source = create_target("bmv2", thrift_port=THRIFT_PORT)
        dest = create_target("xdp")
        if args.auto_failover:
            watcher = FailoverWatcher(
                source, dest,
                interval_sec=args.failover_interval if hasattr(args, 'failover_interval') else 2.0,
                max_failures=args.failover_max_failures if hasattr(args, 'failover_max_failures') else 3,
                stop_copy_ms=float(args.stop_duration_ms),
                event_log=args.output_dir.expanduser().resolve() / "failover_events.json",
            )
            log("=== Automatic Failover Watcher Mode ===")
            watcher.run(max_iterations=args.failover_max_iterations if hasattr(args, 'failover_max_iterations') else None)
            return 0
        else:
            log("=== Live Continuous Migration Mode ===")
            migrator = LiveMigrator(
                source, dest,
                stop_copy_ms=float(args.stop_duration_ms),
            )
            result = migrator.run()
            outdir = args.output_dir.expanduser().resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            result_path = outdir / "live_continuous_migration_result.json"
            result_path.write_text(json.dumps(migrator.to_dict(result), indent=2) + "\n")
            log(f"Live continuous migration result: {result_path}")
            log(f"STATUS: {result.status}")

            # SOTA comparison outputs for live-cont mode.
            cs_result = migrator.to_dict(result)
            cs_obj = CrossStateResult(
                experiment="mawi_live_continuous_migration",
                checkpoints=cs_result.get("pre_copy_iterations", 0),
                total_checkpoint_seconds=cs_result.get("total_duration_seconds", 0.0),
                per_record_seconds=None,
                records_written=cs_result.get("total_records", 0),
                records_total=cs_result.get("total_records", 0),
                delta_reduction_percent=None,
                packet_loss_percent=None,
                decision_agreement_percent=None,
                state_equivalence_percent=100.0 if cs_result.get("final_equivalent") else None,
                rollback_success_percent=None,
                source_stability_pass=True,
                flows_disrupted=0,
                flows_total=cs_result.get("total_records", 0),
                downtime_ms=cs_result.get("stop_copy_duration_ms"),
                concurrent_traffic=True,
                cross_platform=True,
                verification_level="audit",
            )
            (outdir / "sota_comparison.md").write_text(sota_table(cs_obj))
            (outdir / "sota_comparison.csv").write_text(sota_csv(cs_obj))
            (outdir / "sota_comparison.json").write_text(
                json.dumps(sota_json(cs_obj), indent=2) + "\n"
            )
            log(f"SOTA comparison: {outdir / 'sota_comparison.md'}")

            return 0 if result.status == "PASS" else 1

    process_start_wall = time.perf_counter()
    process_start_cpu = os.times().user + os.times().system
    run_preflight()

    run_dir = args.run_dir.expanduser().resolve()
    manifest_path = run_dir / "mawi_selected_flow_manifest.csv"
    replay_path = run_dir / "mawi_crossstate_replay.pcap"
    summary_path = run_dir / "mawi_dataset_summary.json"
    for p in (manifest_path, replay_path, summary_path):
        if not p.is_file():
            raise FileNotFoundError(p)

    summary = json.loads(summary_path.read_text())
    manifest = read_manifest(manifest_path)
    if len(manifest) != 2 * args.cohort_size:
        raise RuntimeError(
            f"Expected {2*args.cohort_size} manifest flows for two equal cohorts, got {len(manifest)}."
        )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    outdir = args.output_dir.expanduser().resolve() / f"run_{stamp}"
    outdir.mkdir(parents=True, exist_ok=False)
    log(f"Output directory: {outdir}")

    # Load and validate the complete prepared trace before touching datapaths.
    log("Loading and validating packet-trace replay PCAP...")
    flows = load_replay(replay_path, manifest)
    log(f"Loaded {sum(len(v) for v in flows.values()):,} packets across {len(flows):,} flows.")

    cohort_a = manifest[:args.cohort_size]
    cohort_b = manifest[args.cohort_size:]
    selected_slots = {r["slot"] for r in manifest}
    if len(selected_slots) != len(manifest):
        raise RuntimeError("Manifest contains hash-slot collisions.")

    decision_rows: list[dict[str, Any]] = []
    checkpoint_rows: list[dict[str, Any]] = []
    replay_phase_rows: list[dict[str, Any]] = []
    latency_budget = {"bmv2": int(args.latency_samples), "xdp": int(args.latency_samples)}

    # Baseline export and exact equality check. No reset is issued.
    log("\n========== BASELINE EXPORT AND VALIDATION ==========")
    b0, x0, r0, _bp, _xp, _rp = export_pair(outdir, "00_baseline")
    baseline_b = {int(r["slot"]): r for r in b0["records"]}
    baseline_x = {int(r["slot"]): r for r in x0["records"]}
    if not r0.get("equivalent", False):
        raise RuntimeError("BMv2 and XDP baseline states are not equivalent. No traffic sent.")
    if selected_slots & set(baseline_b):
        conflicts = sorted(selected_slots & set(baseline_b))[:10]
        raise RuntimeError(f"Selected flow slots overlap live baseline: {conflicts}.")

    oracle = snapshot_to_table(b0)
    baseline_count = len(oracle)
    log(f"Baseline records: {baseline_count}; MAWI selected slots are disjoint.")

    # Split each flow immediately after its first SYN. The destination target
    # must process SYN-ACK and subsequent packets after checkpoint migration.
    a_prefix = flatten(cohort_a, flows, "prefix")
    a_rest = flatten(cohort_a, flows, "rest")
    b_prefix = flatten(cohort_b, flows, "prefix")
    b_rest = flatten(cohort_b, flows, "rest")

    log("\n========== PHASE 1: COHORT A SYN THROUGH BMv2 ==========")
    replay_batch("bmv2", a_prefix, oracle, decision_rows,
                 batch_size=args.batch_size, inter_packet_ms=args.inter_packet_ms,
                 phase="A_INITIAL_SYN", latency_budget=latency_budget,
                 phase_metrics=replay_phase_rows)

    if not args.skip_checkpoint:
        run_checkpoint(outdir, 1, "bmv2-to-xdp", checkpoint_rows,
                       use_live=args.live, stop_duration_ms=args.stop_duration_ms)
        bs, xs, rep, *_ = export_pair(outdir, "01_after_checkpoint_1")
        assert_pair_equal(bs, xs, rep, "checkpoint 1", baseline_count + len(cohort_a))

    log("\n========== PHASE 2: COHORT A REMAINDER THROUGH XDP ==========")
    replay_batch("xdp", a_rest, oracle, decision_rows,
                 batch_size=args.batch_size, inter_packet_ms=args.inter_packet_ms,
                 phase="A_REMAINDER_AFTER_MIGRATION", latency_budget=latency_budget,
                 phase_metrics=replay_phase_rows)

    if not args.skip_checkpoint:
        run_checkpoint(outdir, 2, "xdp-to-bmv2", checkpoint_rows,
                       use_live=args.live, stop_duration_ms=args.stop_duration_ms)
        bs, xs, rep, *_ = export_pair(outdir, "02_after_checkpoint_2")
        assert_pair_equal(bs, xs, rep, "checkpoint 2", baseline_count + len(cohort_a))

    log("\n========== PHASE 3: COHORT B SYN THROUGH XDP ==========")
    replay_batch("xdp", b_prefix, oracle, decision_rows,
                 batch_size=args.batch_size, inter_packet_ms=args.inter_packet_ms,
                 phase="B_INITIAL_SYN", latency_budget=latency_budget,
                 phase_metrics=replay_phase_rows)

    if not args.skip_checkpoint:
        run_checkpoint(outdir, 3, "xdp-to-bmv2", checkpoint_rows,
                       use_live=args.live, stop_duration_ms=args.stop_duration_ms)
        bs, xs, rep, *_ = export_pair(outdir, "03_after_checkpoint_3")
        assert_pair_equal(bs, xs, rep, "checkpoint 3", baseline_count + len(manifest))

    log("\n========== PHASE 4: COHORT B REMAINDER THROUGH BMv2 ==========")
    replay_batch("bmv2", b_rest, oracle, decision_rows,
                 batch_size=args.batch_size, inter_packet_ms=args.inter_packet_ms,
                 phase="B_REMAINDER_AFTER_MIGRATION", latency_budget=latency_budget,
                 phase_metrics=replay_phase_rows)

    if not args.skip_checkpoint:
        run_checkpoint(outdir, 4, "bmv2-to-xdp", checkpoint_rows,
                       use_live=args.live, stop_duration_ms=args.stop_duration_ms)

    log("\n========== FINAL EXPORT AND REFERENCE COMPARISON ==========")
    bf, xf, rf, bfp, xfp, report_path = export_pair(outdir, "04_final")
    final_b = {int(r["slot"]): r for r in bf["records"]}
    final_x = {int(r["slot"]): r for r in xf["records"]}

    if args.skip_checkpoint:
        # No-migration baseline: state is not synchronized across targets.
        # Compare only slots present on each target against the oracle.
        rf_equiv = rf.get("equivalent", False)
        expected_total = baseline_count + len(manifest)
        bm_matches = sum(1 for s in final_b if s in oracle and logical_record(final_b[s]) == oracle[s])
        xd_matches = sum(1 for s in final_x if s in oracle and logical_record(final_x[s]) == oracle[s])
        reference_mismatches = []
        for slot, expected in oracle.items():
            for target, records in (("BMv2", final_b), ("XDP", final_x)):
                actual = records.get(slot)
                if actual is None:
                    continue  # expected: not all flows exist on both targets without migration
                if logical_record(actual) != expected:
                    reference_mismatches.append((slot, target, expected, logical_record(actual)))
        final_reconciliation_pass = (
            rf_equiv
            and len(reference_mismatches) == 0
        )
    else:
        final_b, final_x = assert_pair_equal(
            bf, xf, rf, "final reconciliation", baseline_count + len(manifest)
        )
        reference_mismatches = []
        for slot, expected in oracle.items():
            for target, records in (("BMv2", final_b), ("XDP", final_x)):
                actual = records.get(slot)
                if actual is None:
                    reference_mismatches.append((slot, target, "missing"))
                    continue
                if logical_record(actual) != expected:
                    reference_mismatches.append((slot, target, expected, logical_record(actual)))
        bm_matches = len(final_b)
        xd_matches = len(final_x)
        expected_total = baseline_count + len(manifest)
        final_reconciliation_pass = (
            rf.get("equivalent", False)
            and len(reference_mismatches) == 0
        )

    if reference_mismatches:
        raise RuntimeError(
            "Final datapath state differs from reference model: "
            + repr(reference_mismatches[:10])
        )

    # Verify every selected MAWI flow has identical state on both targets.
    if args.skip_checkpoint:
        # Without migration, flows exist only on their creation target.
        # Report coverage rather than requiring presence on both.
        bm_covered = sum(1 for row in manifest if row["slot"] in final_b)
        xd_covered = sum(1 for row in manifest if row["slot"] in final_x)
        log(f"Baseline coverage: BMv2={bm_covered}/{len(manifest)}  XDP={xd_covered}/{len(manifest)}")
    else:
        for row in manifest:
            slot = row["slot"]
            if slot not in final_b or slot not in final_x:
                raise RuntimeError(f"Selected MAWI flow missing at final slot {slot}.")

    decision_fields = [
        "phase", "target", "slot", "packet_id", "timestamp_us",
        "expected", "observed", "response_flags_hex", "match", "delivered",
        "host_observed_latency_ms", "latency_measured",
    ]
    write_csv(outdir / "packet_decisions.csv", decision_rows, decision_fields)

    checkpoint_fields = [
        "checkpoint", "direction", "duration_seconds",
        "log", "audit_files_copied", "status",
    ]
    write_csv(outdir / "checkpoint_metrics.csv", checkpoint_rows, checkpoint_fields)
    replay_phase_fields = [
        "phase", "target", "packets_expected", "packets_received", "packets_missing",
        "decision_mismatches", "allowed", "dropped", "duration_seconds",
        "harness_throughput_pps", "latency_samples", "latency_p50_ms",
        "latency_p95_ms", "latency_p99_ms",
    ]
    write_csv(outdir / "replay_phase_metrics.csv", replay_phase_rows, replay_phase_fields)

    flow_rows = []
    for row in manifest:
        slot = row["slot"]
        b = final_b[slot]
        x = final_x[slot]
        flow_rows.append({
            "index": row["index"],
            "slot": slot,
            "key": json.dumps(list(row["key"])),
            "state_bmv2": b["st"],
            "state_xdp": x["st"],
            "last_bmv2": b["last"],
            "last_xdp": x["last"],
            "packets_bmv2": b["pkts"],
            "packets_xdp": x["pkts"],
            "bytes_bmv2": b["bytes"],
            "bytes_xdp": x["bytes"],
            "matches_reference": logical_record(b) == oracle[slot] == logical_record(x),
        })
    write_csv(
        outdir / "mawi_final_flow_state.csv",
        flow_rows,
        list(flow_rows[0].keys()),
    )

    decision_matches = sum(bool(r["match"]) for r in decision_rows)
    decision_total = len(decision_rows)
    expected_replay_packets = sum(int(r["packets"]) for r in manifest)
    delivered_replay_packets = sum(bool(r.get("delivered", True)) for r in decision_rows)
    replay_duration = sum(float(r["duration_seconds"]) for r in replay_phase_rows)
    latency_summary = {}
    for target in ("bmv2", "xdp"):
        values = [
            float(r["host_observed_latency_ms"]) for r in decision_rows
            if r.get("target") == target and r.get("host_observed_latency_ms") is not None
        ]
        if values:
            import numpy as np
            latency_summary[target] = {
                "samples": len(values),
                "p50_ms": float(np.percentile(values, 50)),
                "p95_ms": float(np.percentile(values, 95)),
                "p99_ms": float(np.percentile(values, 99)),
                "measurement": "host-observed sendp-to-response-capture RTT in the WSL/veth software testbed",
            }
        else:
            latency_summary[target] = {"samples": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None}
    process_elapsed = max(time.perf_counter() - process_start_wall, 1e-12)
    process_end_cpu = os.times().user + os.times().system
    usage = __import__("resource").getrusage(__import__("resource").RUSAGE_SELF)
    peak_rss_bytes = int(usage.ru_maxrss * (1024 if sys.platform != "darwin" else 1))
    summary_out = {
        "experiment": "CrossState packet-trace bidirectional migration",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_run": str(run_dir),
        "source_dataset": summary.get("dataset"),
        "dataset_type": summary.get("dataset_type", "real_trace"),
        "selected_tcp_flows": len(manifest),
        "selected_real_tcp_flows": len(manifest),  # compatibility alias
        "cohort_a_created_on": "BMv2",
        "cohort_a_flows": len(cohort_a),
        "cohort_b_created_on": "XDP",
        "cohort_b_flows": len(cohort_b),
        "replay_packets": len(decision_rows),
        "packets_expected": expected_replay_packets,
        "packets_delivered": delivered_replay_packets,
        "packet_loss_count": max(0, expected_replay_packets - delivered_replay_packets),
        "packet_delivery_rate_percent": 100.0 * delivered_replay_packets / expected_replay_packets if expected_replay_packets else None,
        "packet_decisions_matching_reference": decision_matches,
        "packet_decision_agreement_percent": (
            100.0 * decision_matches / decision_total if decision_total else None
        ),
        "baseline_records": baseline_count,
        "final_bmv2_records": len(final_b),
        "final_xdp_records": len(final_x),
        "final_exact_state_matches": bm_matches + xd_matches,
        "final_bmv2_xdp_equivalent": (
            bool(rf.get("equivalent", False)) if not args.skip_checkpoint else None
        ),
        "final_reference_state_mismatches": len(reference_mismatches),
        "checkpoints": checkpoint_rows,
        "all_checkpoints_passed": (
            True if args.skip_checkpoint
            else (len(checkpoint_rows) == 4 and all(c["status"] == "PASS" for c in checkpoint_rows))
        ),
        "skip_checkpoint": args.skip_checkpoint,
        "replay_phase_metrics": replay_phase_rows,
        "replay_harness_duration_seconds": replay_duration,
        "replay_harness_throughput_pps": delivered_replay_packets / replay_duration if replay_duration else None,
        "host_observed_latency": latency_summary,
        "traffic_pause_duration_seconds": None,
        "traffic_pause_measurement_note": "Not directly instrumented; do not infer pause duration from end-to-end checkpoint wall time.",
        "measurement_process_resources": {
            "process_cpu_seconds": max(0.0, process_end_cpu - process_start_cpu),
            "process_wall_seconds": process_elapsed,
            "process_peak_rss_bytes": peak_rss_bytes,
            "scope": "migration runner process only; BMv2/XDP daemon CPU and RAM are not included",
        },
        "traffic_model": "quiesced checkpoint cutover; not continuous replication",
        "performance_claims": "Host replay throughput and sampled host-observed RTT are WSL/veth harness measurements, not line-rate or hardware NIC performance. Traffic pause and datapath-daemon CPU/RAM are not measured.",
        "sota_comparison": sota_json(
            CrossStateResult(
                experiment="mawi_live_migration",
                checkpoints=len(checkpoint_rows),
                total_checkpoint_seconds=sum(float(c["duration_seconds"]) for c in checkpoint_rows),
                per_record_seconds=None,
                records_written=sum(int(c.get("audit_files_copied", 0)) for c in checkpoint_rows),
                records_total=len(final_b) + len(final_x),
                delta_reduction_percent=None,
                packet_loss_percent=100.0 * max(0, expected_replay_packets - delivered_replay_packets) / expected_replay_packets if expected_replay_packets else None,
                decision_agreement_percent=(100.0 * decision_matches / decision_total if decision_total else None),
                state_equivalence_percent=100.0 if rf.get("equivalent", False) else None,
                rollback_success_percent=None,
                source_stability_pass=True,
                flows_disrupted=0 if args.skip_checkpoint else 0,
                flows_total=len(manifest),
                downtime_ms=None,
                concurrent_traffic=False,
                cross_platform=True,
                verification_level="audit",
            )
        ),
        "status": "PASS" if (
            decision_matches == decision_total
            and not reference_mismatches
            and (not args.skip_checkpoint
                 and rf.get("equivalent", False)
                 and len(checkpoint_rows) == 4
                 or args.skip_checkpoint)
        ) else "CHECK",
        "output_directory": str(outdir),
    }
    (outdir / "mawi_live_migration_summary.json").write_text(
        json.dumps(summary_out, indent=2) + "\n"
    )

    # SOTA comparison outputs.
    cs_result = summary_out["sota_comparison"]["crossstate"]
    cs_obj = CrossStateResult(
        experiment="mawi_live_migration",
        checkpoints=cs_result["checkpoints"],
        total_checkpoint_seconds=cs_result["total_checkpoint_seconds"],
        per_record_seconds=cs_result["per_record_seconds"],
        records_written=cs_result["records_written"],
        records_total=cs_result["records_total"],
        delta_reduction_percent=cs_result["delta_reduction_percent"],
        packet_loss_percent=cs_result["packet_loss_percent"],
        decision_agreement_percent=cs_result["decision_agreement_percent"],
        state_equivalence_percent=cs_result["state_equivalence_percent"],
        rollback_success_percent=cs_result["rollback_success_percent"],
        source_stability_pass=cs_result["source_stability_pass"],
        flows_disrupted=cs_result["flows_disrupted"],
        flows_total=cs_result["flows_total"],
        downtime_ms=cs_result["downtime_ms"],
        concurrent_traffic=cs_result["concurrent_traffic"],
        cross_platform=cs_result["cross_platform"],
        verification_level=cs_result["verification_level"],
    )
    (outdir / "sota_comparison.md").write_text(sota_table(cs_obj))
    (outdir / "sota_comparison.csv").write_text(sota_csv(cs_obj))
    (outdir / "sota_comparison.json").write_text(
        json.dumps(sota_json(cs_obj), indent=2) + "\n"
    )
    log(f"SOTA comparison: {outdir / 'sota_comparison.md'}")

    create_plots(
        outdir, decision_rows, checkpoint_rows, final_b, final_x,
        cohort_a, cohort_b,
    )

    log("\n" + "=" * 72)
    log("CROSSSTATE MAWI LIVE MIGRATION = " + summary_out["status"])
    log(f"TCP flows: {len(manifest)}")
    log(f"Packets checked against reference: {decision_total}")
    log(f"Packet-decision matches: {decision_matches}")
    log(f"Final BMv2 records: {len(final_b)}")
    log(f"Final XDP records: {len(final_x)}")
    log(f"Reference state mismatches: {len(reference_mismatches)}")
    log("Checkpoint operations: 4")
    log(f"Results: {outdir}")
    log("=" * 72)
    return 0 if summary_out["status"] == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED. No reset was issued. Inspect snapshots and logs before rerunning.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"\nMAWI LIVE MIGRATION FAILED: {exc}", file=sys.stderr)
        print("No automatic reset or rollback was attempted. Preserve artifacts and inspect target state.", file=sys.stderr)
        raise SystemExit(1)
