#!/usr/bin/env python3
"""
CrossState real-MAWI replay with bidirectional BMv2/XDP migration.

Four quiesced checkpoints:
  1. BMv2 -> XDP
  2. XDP -> BMv2
  3. XDP -> BMv2
  4. BMv2 -> XDP

Each packet decision is compared against ref.model.step().
No datapath reset or automatic packet retry is performed.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import AsyncSniffer, Ether, get_if_hwaddr, sendp
from ref.model import Ev, canon, slot_of, step
from scripts import sync_state

THRIFT_PORT = 9090
ETHERTYPE = 0x88B5
IP_OFFSET = 27


def log(message: str) -> None:
    print(message, flush=True)


def run_preflight() -> None:
    if os.geteuid() != 0:
        raise RuntimeError(
            "Run with sudo and the CrossState venv PYTHONPATH."
        )

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
            "Runtime interfaces are missing: "
            + ", ".join(missing)
            + ". Start the isolated runtime first using "
            "bash scripts/crossstate_start_runtime.sh. "
            "This experiment will not create interfaces or restart targets."
        )

    ss = subprocess.run(
        ["ss", "-lnt"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    if ":9090" not in ss:
        raise RuntimeError("BMv2 Thrift port 9090 is not listening.")

    net = subprocess.run(
        ["bpftool", "net", "show"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    if "cs-xdp" not in net:
        raise RuntimeError("No XDP attachment found on cs-xdp.")

    maps = subprocess.run(
        ["bpftool", "map", "show"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    if "flow_state" not in maps:
        raise RuntimeError("The XDP flow_state map was not found.")

    log("PREFLIGHT = PASS")


def read_manifest(path: Path) -> list[dict[str, Any]]:
    rows = []

    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            row["index"] = int(row["index"])
            row["slot"] = int(row["slot"])
            row["key"] = tuple(
                int(v) for v in json.loads(row["key"])
            )
            rows.append(row)

    rows.sort(key=lambda r: r["index"])

    if not rows:
        raise RuntimeError("MAWI flow manifest is empty.")

    return rows


def parse_replay_frame(frame: bytes) -> dict[str, Any]:
    if (
        len(frame) < 14 + 13 + 40
        or frame[12:14] != b"\x88\xb5"
    ):
        raise ValueError("Invalid CrossState replay Ethernet frame.")

    if frame[25:27] != b"\x08\x00":
        raise ValueError("Replay shim inner EtherType is not IPv4.")

    ts = int.from_bytes(frame[14:20], "big")
    pkt_id = int.from_bytes(frame[20:24], "big")
    direction = frame[24] & 0x01

    ipoff = IP_OFFSET
    version = frame[ipoff] >> 4
    ihl = (frame[ipoff] & 0x0F) * 4

    if (
        version != 4
        or ihl < 20
        or len(frame) < ipoff + ihl + 20
    ):
        raise ValueError("Invalid IPv4/TCP packet in replay PCAP.")

    ip_total = struct.unpack(
        "!H", frame[ipoff + 2:ipoff + 4]
    )[0]

    if ip_total < ihl + 20 or frame[ipoff + 9] != 6:
        raise ValueError("Expected a complete IPv4/TCP header.")

    src_ip = int.from_bytes(frame[ipoff + 12:ipoff + 16], "big")
    dst_ip = int.from_bytes(frame[ipoff + 16:ipoff + 20], "big")

    tcp_off = ipoff + ihl
    sport, dport = struct.unpack("!HH", frame[tcp_off:tcp_off + 4])
    tcp_flags = frame[tcp_off + 13]

    event = Ev(
        src_ip,
        sport,
        dst_ip,
        dport,
        6,
        bool(direction),
        bool(tcp_flags & 0x02),
        bool(tcp_flags & 0x10),
        bool(tcp_flags & 0x01),
        bool(tcp_flags & 0x04),
        ip_total,
        ts,
    )

    key = tuple(int(v) for v in canon(event))
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
        "event": event,
    }


def load_replay(
    path: Path,
    manifest: list[dict[str, Any]],
) -> dict[int, list[dict[str, Any]]]:

    by_key = {r["key"]: r for r in manifest}

    if len(by_key) != len(manifest):
        raise RuntimeError("Duplicate flow key in manifest.")

    flows: dict[int, list[dict[str, Any]]] = defaultdict(list)
    seen_pkt_ids = set()

    with path.open("rb") as fh:
        hdr = fh.read(24)

        if len(hdr) != 24:
            raise RuntimeError("Invalid replay PCAP header.")

        magic = hdr[:4]

        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise RuntimeError("Expected a microsecond classic PCAP.")

        linktype = struct.unpack(endian + "I", hdr[20:24])[0]

        if linktype != 1:
            raise RuntimeError(
                f"Expected Ethernet PCAP linktype 1, got {linktype}."
            )

        packet_records = 0

        while True:
            rec = fh.read(16)

            if not rec:
                break

            if len(rec) != 16:
                raise RuntimeError("Truncated PCAP record header.")

            _sec, _usec, incl, _orig = struct.unpack(
                endian + "IIII", rec
            )

            if incl > 64 * 1024 * 1024:
                raise RuntimeError("Unreasonable PCAP packet size.")

            frame = fh.read(incl)

            if len(frame) != incl:
                raise RuntimeError("Truncated PCAP frame.")

            packet = parse_replay_frame(frame)
            row = by_key.get(packet["key"])

            if row is None:
                raise RuntimeError(
                    f"Packet references a flow absent from manifest: "
                    f"{packet['key']}"
                )

            if packet["slot"] != row["slot"]:
                raise RuntimeError(
                    f"Slot mismatch for manifest flow {row['index']}."
                )

            if packet["pkt_id"] in seen_pkt_ids:
                raise RuntimeError(
                    f"Duplicate packet identifier {packet['pkt_id']}."
                )

            seen_pkt_ids.add(packet["pkt_id"])
            packet_records += 1
            flows[row["index"]].append(packet)

    expected_total = sum(int(r["packets"]) for r in manifest)

    if packet_records != expected_total:
        raise RuntimeError(
            f"Replay/manifest packet count mismatch: "
            f"{packet_records} vs {expected_total}."
        )

    for row in manifest:
        seq = flows.get(row["index"], [])

        if len(seq) != int(row["packets"]):
            raise RuntimeError(
                f"Flow {row['index']} packet count differs from manifest."
            )

        if not seq:
            raise RuntimeError(
                f"Flow {row['index']} has no replay packets."
            )

        first = seq[0]

        if (
            not (first["tcp_flags"] & 0x02)
            or (first["tcp_flags"] & 0x10)
            or first["direction"] != 1
        ):
            raise RuntimeError(
                f"Flow {row['index']} does not begin with "
                "an inside initiating SYN."
            )

        saw_synack = False
        saw_final_ack = False

        for pkt in seq[1:]:
            flags = pkt["tcp_flags"]

            if (
                (flags & 0x12) == 0x12
                and pkt["direction"] == 0
            ):
                saw_synack = True

            elif (
                saw_synack
                and (flags & 0x10)
                and not (flags & 0x02)
                and pkt["direction"] == 1
            ):
                saw_final_ack = True
                break

        if not saw_synack or not saw_final_ack:
            raise RuntimeError(
                f"Flow {row['index']} is missing an observed "
                "TCP handshake leg."
            )

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


def logical_record(rec: dict[str, Any]) -> tuple:
    return (
        tuple(int(v) for v in rec["key"]),
        int(rec["st"]),
        int(rec["last"]),
        int(rec["pkts"]),
        int(rec["bytes"]),
    )


def assert_pair_equal(
    bs,
    xs,
    report,
    label: str,
    expected_count: int | None = None,
):
    if not report.get("equivalent", False):
        raise RuntimeError(
            f"BMv2/XDP state mismatch after {label}."
        )

    bmap = {
        int(r["slot"]): r for r in bs["records"]
    }
    xmap = {
        int(r["slot"]): r for r in xs["records"]
    }

    if set(bmap) != set(xmap):
        raise RuntimeError(
            f"Slot sets differ after {label}."
        )

    for slot in bmap:
        if logical_record(bmap[slot]) != logical_record(xmap[slot]):
            raise RuntimeError(
                f"Logical record differs at slot {slot} after {label}."
            )

    if (
        expected_count is not None
        and len(bmap) != expected_count
    ):
        raise RuntimeError(
            f"Expected {expected_count} records after {label}, "
            f"got {len(bmap)}."
        )

    return bmap, xmap


def export_pair(outdir: Path, label: str):
    bpath = outdir / f"{label}_bmv2.json"
    xpath = outdir / f"{label}_xdp.json"
    rpath = outdir / f"{label}_comparison.json"

    bs = sync_state.export_state("bmv2", bpath, THRIFT_PORT)
    xs = sync_state.export_state("xdp", xpath, THRIFT_PORT)
    report = sync_state.compare(bpath, xpath, rpath)

    return bs, xs, report, bpath, xpath, rpath


def stream_subprocess(
    command: list[str],
    logfile: Path,
    label: str,
) -> float:
    start = time.perf_counter()
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{ROOT}:{env.get('PYTHONPATH', '')}"

    with logfile.open("w", encoding="utf-8") as out:
        proc = subprocess.Popen(
            command,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        assert proc.stdout is not None

        for line in proc.stdout:
            print(line, end="", flush=True)
            out.write(line)
            out.flush()

        rc = proc.wait()

    elapsed = time.perf_counter() - start

    if rc:
        raise RuntimeError(
            f"{label} failed with exit code {rc}; see {logfile}."
        )

    return elapsed


def run_checkpoint(
    outdir: Path,
    ordinal: int,
    direction: str,
    checkpoints: list[dict[str, Any]],
) -> None:

    log(
        f"\n========== MAWI CHECKPOINT "
        f"{ordinal}: {direction} =========="
    )

    state_dir = ROOT / "artifacts" / "state"
    before = {
        p.resolve() for p in state_dir.glob("sync_*")
    }

    logfile = outdir / f"checkpoint_{ordinal}_{direction}.log"

    elapsed = stream_subprocess(
        [
            sys.executable,
            str(ROOT / "scripts" / "sync_state.py"),
            "--direction",
            direction,
            "--apply",
            "--traffic-quiesced",
            "--thrift-port",
            str(THRIFT_PORT),
        ],
        logfile,
        f"checkpoint {ordinal} {direction}",
    )

    new_files = [
        p for p in state_dir.glob("sync_*")
        if p.resolve() not in before
    ]

    audit_dir = (
        outdir / "checkpoint_audits" / f"checkpoint_{ordinal}"
    )
    audit_dir.mkdir(parents=True, exist_ok=True)

    for path in new_files:
        if path.is_file():
            shutil.copy2(path, audit_dir / path.name)

    checkpoints.append({
        "checkpoint": ordinal,
        "direction": direction,
        "duration_seconds": elapsed,
        "log": str(logfile),
        "audit_files_copied": len(new_files),
        "status": "PASS",
    })

    log(
        f"CHECKPOINT_{ordinal} = PASS "
        f"({elapsed:.3f} seconds)"
    )


def target_ifaces(target: str):
    if target == "bmv2":
        return "cs-host", "cs-bmv2", "cs-host"

    if target == "xdp":
        return "cs-xdp-host", "cs-xdp", "cs-xdp"

    raise ValueError(target)


def replay_batch(
    target: str,
    packets: list[dict[str, Any]],
    oracle: dict[int, tuple],
    decision_rows: list[dict[str, Any]],
    *,
    batch_size: int,
    inter_packet_ms: float,
    phase: str,
) -> None:

    if not packets:
        log(f"{phase}: no packets in this segment; skipped.")
        return

    tx, peer, capture = target_ifaces(target)

    tx_mac = bytes.fromhex(
        get_if_hwaddr(tx).replace(":", "")
    )
    peer_mac = bytes.fromhex(
        get_if_hwaddr(peer).replace(":", "")
    )

    if len(tx_mac) != 6 or len(peer_mac) != 6:
        raise RuntimeError("Could not read interface MAC addresses.")

    sent = 0
    allowed_count = 0
    dropped_count = 0

    for offset in range(0, len(packets), batch_size):
        batch = packets[offset:offset + batch_size]

        frames = []
        expected = {}
        packet_by_id = {}

        # Evaluate in the exact per-flow replay order.
        for pkt in batch:
            pktid = int(pkt["pkt_id"])

            if pktid in expected:
                raise RuntimeError(
                    f"Duplicate packet ID in replay batch: {pktid}"
                )

            decision = int(step(oracle, pkt["event"]))

            expected[pktid] = decision
            packet_by_id[pktid] = pkt

            frame = bytearray(pkt["frame"])
            frame[0:6] = peer_mac
            frame[6:12] = tx_mac
            frames.append(Ether(bytes(frame)))

        sniffer = AsyncSniffer(iface=capture, store=True)
        sniffer.start()
        time.sleep(0.12)

        try:
            sendp(
                frames,
                iface=tx,
                inter=max(0.0, inter_packet_ms / 1000.0),
                verbose=False,
            )
            time.sleep(0.30)
            captured = sniffer.stop()

        except Exception:
            try:
                sniffer.stop()
            except Exception:
                pass
            raise

        observed: dict[int, list[int]] = defaultdict(list)

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
            flag_list = observed.get(pktid, [])

            if not flag_list:
                missing.append(pktid)
                continue

            response_flags = flag_list[-1]
            actual_decision = (
                1 if (response_flags & 0x04) else 0
            )

            if actual_decision != expected_decision:
                mismatches.append((
                    pktid,
                    expected_decision,
                    actual_decision,
                    response_flags,
                ))

            if actual_decision:
                allowed_count += 1
            else:
                dropped_count += 1

            packet = packet_by_id[pktid]

            decision_rows.append({
                "phase": phase,
                "target": target,
                "slot": packet["slot"],
                "packet_id": pktid,
                "timestamp_us": packet["ts"],
                "expected": (
                    "ALLOW" if expected_decision else "DROP"
                ),
                "observed": (
                    "ALLOW" if actual_decision else "DROP"
                ),
                "response_flags_hex": f"0x{response_flags:02x}",
                "match": (
                    actual_decision == expected_decision
                ),
            })

        sent += len(batch)

        log(
            f"{target.upper()} {phase}: "
            f"{sent}/{len(packets)} packets checked; "
            f"allowed={allowed_count}, dropped={dropped_count}"
        )

        if missing or mismatches:
            raise RuntimeError(
                f"Packet replay validation failed in {phase} "
                f"on {target}. Missing={len(missing)} "
                f"(first={missing[:10]}), "
                f"decision mismatches={len(mismatches)} "
                f"(first={mismatches[:10]}). "
                "No packet retries were issued."
            )

    log(f"{phase} on {target.upper()} = PASS ({sent} packets)")


def flatten(
    rows: list[dict[str, Any]],
    flows: dict[int, list[dict[str, Any]]],
    which: str,
) -> list[dict[str, Any]]:

    result = []

    for row in rows:
        seq = flows[row["index"]]

        if which == "prefix":
            result.append(seq[0])
        else:
            result.extend(seq[1:])

    return result


def write_csv(
    path: Path,
    rows: list[dict[str, Any]],
    fields: list[str],
) -> None:

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def create_plots(
    outdir: Path,
    decisions: list[dict[str, Any]],
    checkpoints: list[dict[str, Any]],
    final_b: dict[int, dict],
    final_x: dict[int, dict],
    cohort_a: list[dict],
    cohort_b: list[dict],
) -> None:

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        log(
            "Matplotlib unavailable; CSV/JSON results saved, "
            "plots skipped."
        )
        return

    plotdir = outdir / "plots_migration"
    plotdir.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 9,
        "axes.titlesize": 11,
        "axes.labelsize": 9,
        "savefig.facecolor": "white",
        "figure.facecolor": "white",
        "axes.grid": True,
        "grid.alpha": 0.22,
    })

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(
            plotdir / f"{name}.pdf",
            bbox_inches="tight",
        )
        fig.savefig(
            plotdir / f"{name}.svg",
            bbox_inches="tight",
        )
        fig.savefig(
            plotdir / f"{name}.png",
            dpi=600,
            bbox_inches="tight",
        )
        plt.close(fig)
        log(f"Plot saved: {name}")

    # 1. Final state equivalence.
    fig, ax = plt.subplots(figsize=(6.4, 4.2))

    exact = sum(
        1 for slot in final_b
        if (
            slot in final_x
            and logical_record(final_b[slot])
            == logical_record(final_x[slot])
        )
    )

    labels = ["BMv2", "XDP", "Exact matches"]
    values = [len(final_b), len(final_x), exact]

    bars = ax.bar(
        labels,
        values,
        color=["#2878B5", "#E87524", "#31966B"],
    )
    ax.set_ylabel("Flow records")
    ax.set_title("Final Cross-Target State Equivalence")

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:,}",
            ha="center",
            va="bottom",
        )

    save(fig, "01_final_state_equivalence")

    # 2 and 3. Counter parity.
    slots = sorted(set(final_b) & set(final_x))

    for field, label, name in [
        ("pkts", "Packet counter", "02_packet_counter_parity"),
        ("bytes", "Byte counter", "03_byte_counter_parity"),
    ]:
        bv = [int(final_b[s][field]) for s in slots]
        xv = [int(final_x[s][field]) for s in slots]

        fig, ax = plt.subplots(figsize=(5.8, 5.3))
        ax.scatter(bv, xv, s=16, alpha=0.45)

        upper = max(bv + xv + [1])
        ax.plot(
            [0, upper],
            [0, upper],
            "r--",
            label="y = x",
        )

        ax.set_xlabel(f"BMv2 {label}")
        ax.set_ylabel(f"XDP {label}")
        ax.set_title(f"{label} Agreement Across Final Flow Records")
        ax.legend()
        save(fig, name)

    # 4. TCP state distribution.
    names = {1: "NEW", 2: "EST", 3: "CLOSED"}
    states = ["NEW", "EST", "CLOSED"]

    bc = Counter(
        names.get(int(r["st"]), "OTHER")
        for r in final_b.values()
    )
    xc = Counter(
        names.get(int(r["st"]), "OTHER")
        for r in final_x.values()
    )

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    pos = list(range(3))
    width = 0.36

    ax.bar(
        [p - width / 2 for p in pos],
        [bc[n] for n in states],
        width,
        label="BMv2",
    )
    ax.bar(
        [p + width / 2 for p in pos],
        [xc[n] for n in states],
        width,
        label="XDP",
    )

    ax.set_xticks(pos)
    ax.set_xticklabels(states)
    ax.set_ylabel("Flow records")
    ax.set_title("Final TCP State Distribution")
    ax.legend()
    save(fig, "04_tcp_state_distribution")

    # 5. Reference-versus-datapath confusion matrix.
    expected = [
        1 if r["expected"] == "ALLOW" else 0
        for r in decisions
    ]
    observed = [
        1 if r["observed"] == "ALLOW" else 0
        for r in decisions
    ]

    matrix = np.zeros((2, 2), dtype=int)

    for e, o in zip(expected, observed):
        matrix[e, o] += 1

    fig, ax = plt.subplots(figsize=(5.2, 4.5))
    im = ax.imshow(matrix, cmap="Blues")

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["DROP", "ALLOW"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["DROP", "ALLOW"])
    ax.set_xlabel("Datapath decision")
    ax.set_ylabel("Reference decision")
    ax.set_title("Reference-to-Datapath Packet Decision Agreement")

    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                f"{matrix[i, j]:,}",
                ha="center",
                va="center",
            )

    fig.colorbar(im, ax=ax, label="Packet count")
    save(fig, "05_packet_decision_confusion_matrix")

    # 6. Decision agreement by target.
    target_stats = {}

    for target in ("bmv2", "xdp"):
        rows = [
            r for r in decisions
            if r["target"] == target
        ]

        target_stats[target] = (
            100 * sum(bool(r["match"]) for r in rows) / len(rows)
            if rows else 0
        )

    fig, ax = plt.subplots(figsize=(5.8, 4.2))

    bars = ax.bar(
        ["BMv2", "XDP"],
        [target_stats["bmv2"], target_stats["xdp"]],
        color=["#2878B5", "#E87524"],
    )

    ax.set_ylim(0, 105)
    ax.set_ylabel("Decision agreement (%)")
    ax.set_title("Packet Decision Agreement by Datapath")

    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{bar.get_height():.2f}%",
            ha="center",
            va="bottom",
        )

    save(fig, "06_decision_agreement_by_target")

    # 7. Checkpoint durations.
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    labels = [
        f"CP{r['checkpoint']}\n{r['direction']}"
        for r in checkpoints
    ]
    vals = [
        r["duration_seconds"] for r in checkpoints
    ]

    bars = ax.bar(
        range(len(vals)),
        vals,
        color=[
            "#2878B5", "#E87524",
            "#31966B", "#8064A2",
        ][:len(vals)],
    )

    ax.set_xticks(range(len(vals)))
    ax.set_xticklabels(labels)
    ax.set_ylabel("Elapsed checkpoint time (seconds)")
    ax.set_title("Quiesced Checkpoint Execution Time")

    for bar, value in zip(bars, vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.2f}",
            ha="center",
            va="bottom",
        )

    save(fig, "07_checkpoint_duration")

    # 8. Cohort sizes.
    fig, ax = plt.subplots(figsize=(5.8, 4.2))

    ax.bar(
        ["Cohort A: BMv2 first", "Cohort B: XDP first"],
        [len(cohort_a), len(cohort_b)],
        color=["#2878B5", "#E87524"],
    )

    ax.set_ylabel("MAWI TCP flows")
    ax.set_title("Bidirectional Migration Cohort Sizes")
    save(fig, "08_migration_cohort_sizes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path(
            "/mnt/e/SDN/datasets/mawi/processed/"
            "run_20261113T123336Z"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(
            "/mnt/e/SDN/datasets/mawi/live_migration"
        ),
    )
    parser.add_argument(
        "--cohort-size",
        type=int,
        default=500,
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=40,
    )
    parser.add_argument(
        "--inter-packet-ms",
        type=float,
        default=0.2,
    )
    parser.add_argument(
        "--traffic-quiesced",
        action="store_true",
    )

    args = parser.parse_args()

    if not args.traffic_quiesced:
        parser.error(
            "Checkpoint apply requires --traffic-quiesced. "
            "Use only on isolated test datapaths."
        )

    if args.cohort_size < 1 or args.batch_size < 1:
        parser.error("cohort-size and batch-size must be positive.")

    if args.inter_packet_ms < 0:
        parser.error("inter-packet-ms cannot be negative.")

    run_preflight()

    run_dir = args.run_dir.expanduser().resolve()

    manifest_path = (
        run_dir / "mawi_selected_flow_manifest.csv"
    )
    replay_path = (
        run_dir / "mawi_crossstate_replay.pcap"
    )
    summary_path = (
        run_dir / "mawi_dataset_summary.json"
    )

    for path in (manifest_path, replay_path, summary_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    summary = json.loads(summary_path.read_text())
    manifest = read_manifest(manifest_path)

    if len(manifest) != 2 * args.cohort_size:
        raise RuntimeError(
            f"Expected {2 * args.cohort_size} manifest flows "
            f"for two equal cohorts, got {len(manifest)}."
        )

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )

    outdir = (
        args.output_dir.expanduser().resolve()
        / f"run_{stamp}"
    )
    outdir.mkdir(parents=True, exist_ok=False)

    log(f"Output directory: {outdir}")

    # Read and validate complete prepared trace before datapath mutation.
    log("\n========== LOAD AND VALIDATE MAWI TRACE ==========")

    flows = load_replay(replay_path, manifest)

    log(
        f"Loaded {sum(len(v) for v in flows.values()):,} packets "
        f"across {len(flows):,} flows."
    )

    cohort_a = manifest[:args.cohort_size]
    cohort_b = manifest[args.cohort_size:]

    selected_slots = {
        r["slot"] for r in manifest
    }

    if len(selected_slots) != len(manifest):
        raise RuntimeError(
            "Manifest contains hash-slot collisions."
        )

    decision_rows: list[dict[str, Any]] = []
    checkpoint_rows: list[dict[str, Any]] = []

    # Baseline export. No reset is issued.
    log("\n========== BASELINE EXPORT AND VALIDATION ==========")

    b0, x0, r0, *_ = export_pair(outdir, "00_baseline")

    baseline_b = {
        int(r["slot"]): r for r in b0["records"]
    }
    baseline_x = {
        int(r["slot"]): r for r in x0["records"]
    }

    if not r0.get("equivalent", False):
        raise RuntimeError(
            "BMv2 and XDP baseline states are not equivalent. "
            "No test traffic was sent."
        )

    if selected_slots & set(baseline_b):
        conflicts = sorted(
            selected_slots & set(baseline_b)
        )[:10]

        raise RuntimeError(
            f"MAWI selected slots overlap live baseline: {conflicts}."
        )

    oracle = snapshot_to_table(b0)
    baseline_count = len(oracle)

    log(
        f"Baseline records: {baseline_count}; "
        "MAWI selected slots are disjoint."
    )

    # Each cohort starts with its SYN; all later packets form its remainder.
    a_prefix = flatten(cohort_a, flows, "prefix")
    a_rest = flatten(cohort_a, flows, "rest")
    b_prefix = flatten(cohort_b, flows, "prefix")
    b_rest = flatten(cohort_b, flows, "rest")

    # ---------------------------------------------------------
    # COHORT A: BMv2 -> XDP -> BMv2
    # ---------------------------------------------------------
    log("\n========== PHASE 1: COHORT A SYN THROUGH BMv2 ==========")

    replay_batch(
        "bmv2",
        a_prefix,
        oracle,
        decision_rows,
        batch_size=args.batch_size,
        inter_packet_ms=args.inter_packet_ms,
        phase="A_INITIAL_SYN",
    )

    run_checkpoint(
        outdir, 1, "bmv2-to-xdp", checkpoint_rows
    )

    bs, xs, rep, *_ = export_pair(
        outdir, "01_after_checkpoint_1"
    )

    assert_pair_equal(
        bs, xs, rep,
        "checkpoint 1",
        baseline_count + len(cohort_a),
    )

    log("\n========== PHASE 2: COHORT A REMAINDER THROUGH XDP ==========")

    replay_batch(
        "xdp",
        a_rest,
        oracle,
        decision_rows,
        batch_size=args.batch_size,
        inter_packet_ms=args.inter_packet_ms,
        phase="A_REMAINDER_AFTER_MIGRATION",
    )

    run_checkpoint(
        outdir, 2, "xdp-to-bmv2", checkpoint_rows
    )

    bs, xs, rep, *_ = export_pair(
        outdir, "02_after_checkpoint_2"
    )

    assert_pair_equal(
        bs, xs, rep,
        "checkpoint 2",
        baseline_count + len(cohort_a),
    )

    # ---------------------------------------------------------
    # COHORT B: XDP -> BMv2 -> XDP
    # ---------------------------------------------------------
    log("\n========== PHASE 3: COHORT B SYN THROUGH XDP ==========")

    replay_batch(
        "xdp",
        b_prefix,
        oracle,
        decision_rows,
        batch_size=args.batch_size,
        inter_packet_ms=args.inter_packet_ms,
        phase="B_INITIAL_SYN",
    )

    run_checkpoint(
        outdir, 3, "xdp-to-bmv2", checkpoint_rows
    )

    bs, xs, rep, *_ = export_pair(
        outdir, "03_after_checkpoint_3"
    )

    assert_pair_equal(
        bs, xs, rep,
        "checkpoint 3",
        baseline_count + len(manifest),
    )

    log("\n========== PHASE 4: COHORT B REMAINDER THROUGH BMv2 ==========")

    replay_batch(
        "bmv2",
        b_rest,
        oracle,
        decision_rows,
        batch_size=args.batch_size,
        inter_packet_ms=args.inter_packet_ms,
        phase="B_REMAINDER_AFTER_MIGRATION",
    )

    run_checkpoint(
        outdir, 4, "bmv2-to-xdp", checkpoint_rows
    )

    # ---------------------------------------------------------
    # Final state reconciliation and reference comparison.
    # ---------------------------------------------------------
    log("\n========== FINAL EXPORT AND REFERENCE COMPARISON ==========")

    bf, xf, rf, bfp, xfp, report_path = export_pair(
        outdir, "04_final"
    )

    final_b, final_x = assert_pair_equal(
        bf,
        xf,
        rf,
        "final reconciliation",
        baseline_count + len(manifest),
    )

    reference_mismatches = []

    for slot, expected in oracle.items():
        for target, records in (
            ("BMv2", final_b),
            ("XDP", final_x),
        ):
            actual = records.get(slot)

            if actual is None:
                reference_mismatches.append(
                    (slot, target, "missing")
                )
                continue

            if logical_record(actual) != expected:
                reference_mismatches.append(
                    (
                        slot,
                        target,
                        expected,
                        logical_record(actual),
                    )
                )

    if reference_mismatches:
        raise RuntimeError(
            "Final datapath state differs from reference model: "
            + repr(reference_mismatches[:10])
        )

    for row in manifest:
        slot = row["slot"]

        if slot not in final_b or slot not in final_x:
            raise RuntimeError(
                f"Selected MAWI flow missing at final slot {slot}."
            )

    # Save packet-level decisions.
    decision_fields = [
        "phase",
        "target",
        "slot",
        "packet_id",
        "timestamp_us",
        "expected",
        "observed",
        "response_flags_hex",
        "match",
    ]

    write_csv(
        outdir / "packet_decisions.csv",
        decision_rows,
        decision_fields,
    )

    # Save checkpoint measurements.
    checkpoint_fields = [
        "checkpoint",
        "direction",
        "duration_seconds",
        "log",
        "audit_files_copied",
        "status",
    ]

    write_csv(
        outdir / "checkpoint_metrics.csv",
        checkpoint_rows,
        checkpoint_fields,
    )

    # Save final per-flow states.
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
            "matches_reference": (
                logical_record(b)
                == oracle[slot]
                == logical_record(x)
            ),
        })

    write_csv(
        outdir / "mawi_final_flow_state.csv",
        flow_rows,
        list(flow_rows[0].keys()),
    )

    decision_matches = sum(
        bool(r["match"]) for r in decision_rows
    )
    decision_total = len(decision_rows)

    summary_out = {
        "experiment": (
            "CrossState MAWI real-packet bidirectional migration"
        ),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_run": str(run_dir),
        "source_dataset": summary.get("dataset"),
        "selected_real_tcp_flows": len(manifest),
        "cohort_a_created_on": "BMv2",
        "cohort_a_flows": len(cohort_a),
        "cohort_b_created_on": "XDP",
        "cohort_b_flows": len(cohort_b),
        "replay_packets": len(decision_rows),
        "packet_decisions_matching_reference": decision_matches,
        "packet_decision_agreement_percent": (
            100.0 * decision_matches / decision_total
            if decision_total else None
        ),
        "baseline_records": baseline_count,
        "final_bmv2_records": len(final_b),
        "final_xdp_records": len(final_x),
        "final_exact_state_matches": len(final_b),
        "final_bmv2_xdp_equivalent": bool(
            rf.get("equivalent", False)
        ),
        "final_reference_state_mismatches": len(
            reference_mismatches
        ),
        "checkpoints": checkpoint_rows,
        "all_checkpoints_passed": (
            len(checkpoint_rows) == 4
            and all(
                c["status"] == "PASS"
                for c in checkpoint_rows
            )
        ),
        "traffic_model": (
            "Quiesced checkpoint cutover; not continuous replication."
        ),
        "performance_claims": (
            "No line-rate, hardware throughput or latency claim is made."
        ),
        "status": "PASS" if (
            decision_matches == decision_total
            and not reference_mismatches
            and rf.get("equivalent", False)
            and len(checkpoint_rows) == 4
        ) else "CHECK",
        "output_directory": str(outdir),
    }

    summary_path = outdir / "mawi_live_migration_summary.json"
    summary_path.write_text(
        json.dumps(summary_out, indent=2) + "\n"
    )

    create_plots(
        outdir,
        decision_rows,
        checkpoint_rows,
        final_b,
        final_x,
        cohort_a,
        cohort_b,
    )

    log("\n" + "=" * 72)
    log("CROSSSTATE MAWI LIVE MIGRATION = " + summary_out["status"])
    log(f"Real TCP flows: {len(manifest)}")
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
        print(
            "\nINTERRUPTED. No reset was issued. "
            "Inspect snapshots and logs before rerunning.",
            file=sys.stderr,
        )
        raise SystemExit(130)

    except Exception as exc:
        print(
            f"\nMAWI LIVE MIGRATION FAILED: {exc}",
            file=sys.stderr,
        )
        print(
            "No automatic reset or rollback was attempted. "
            "Preserve artifacts and inspect target state.",
            file=sys.stderr,
        )
        raise SystemExit(1)
