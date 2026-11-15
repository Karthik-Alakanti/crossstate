#!/usr/bin/env python3
"""CrossState demo: MAWI subset, simulation, and live BMv2/XDP migration."""

from __future__ import annotations

import argparse
import csv
import json
import os
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import ALLOW, Ev, canon, slot_of, step
from scripts import sync_state
from scripts.mawi_crossstate_live_migration import (
    load_replay,
    parse_replay_frame,
    read_manifest,
    replay_batch,
    snapshot_to_table,
)

THRIFT_PORT = 9090
DEFAULT_RUN = Path(
    "/mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z"
)


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def log(message):
    print(message, flush=True)


def pcap_header(path):
    with path.open("rb") as f:
        header = f.read(24)

    if len(header) != 24:
        raise RuntimeError(f"Invalid PCAP header: {path}")

    if header[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif header[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise RuntimeError("Expected microsecond classic PCAP.")

    if struct.unpack(endian + "I", header[20:24])[0] != 1:
        raise RuntimeError("Expected Ethernet PCAP linktype 1.")

    return header, endian


def iter_pcap(path):
    _, endian = pcap_header(path)

    with path.open("rb") as f:
        f.seek(24)

        while True:
            rec = f.read(16)

            if not rec:
                break

            if len(rec) != 16:
                raise RuntimeError("Truncated PCAP record header.")

            _, _, incl, _ = struct.unpack(endian + "IIII", rec)
            frame = f.read(incl)

            if len(frame) != incl:
                raise RuntimeError("Truncated PCAP frame.")

            yield rec, frame


def select_whole_flows(rows, flows, packet_budget, flow_cap):
    selected = []
    used = 0

    for row in rows:
        count = len(flows.get(row["index"], []))

        if not count:
            continue

        if flow_cap is not None and len(selected) >= flow_cap:
            break

        if used + count <= packet_budget:
            selected.append(row)
            used += count

    # The migration runner requires two equal cohorts.
    if len(selected) % 2:
        selected.pop()

    if len(selected) < 2:
        raise RuntimeError(
            "Fewer than two complete flows fit the packet budget. "
            "Increase --max-packets."
        )

    slots = [int(r["slot"]) for r in selected]

    if len(slots) != len(set(slots)):
        raise RuntimeError("Selected flows contain a hash-slot collision.")

    return selected


def prepare_subset(source_dir, rows, destination):
    destination.mkdir(parents=True, exist_ok=False)

    src_manifest = source_dir / "mawi_selected_flow_manifest.csv"
    src_pcap = source_dir / "mawi_crossstate_replay.pcap"
    src_summary = source_dir / "mawi_dataset_summary.json"

    for path in (src_manifest, src_pcap, src_summary):
        if not path.is_file():
            raise FileNotFoundError(path)

    with src_manifest.open(newline="", encoding="utf-8") as f:
        fields = list(csv.DictReader(f).fieldnames or [])

    with (destination / "mawi_selected_flow_manifest.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for row in rows:
            out = dict(row)
            out["key"] = json.dumps(list(row["key"]))
            writer.writerow(out)

    wanted = {tuple(r["key"]) for r in rows}
    counts = Counter()

    header, _ = pcap_header(src_pcap)

    with (destination / "mawi_crossstate_replay.pcap").open("wb") as out:
        out.write(header)

        for rec, frame in iter_pcap(src_pcap):
            packet = parse_replay_frame(frame)

            if packet["key"] in wanted:
                out.write(rec)
                out.write(frame)
                counts[packet["key"]] += 1

    expected = {
        tuple(r["key"]): int(r["packets"])
        for r in rows
    }

    errors = [
        (key, expected[key], counts.get(key, 0))
        for key in expected
        if expected[key] != counts.get(key, 0)
    ]

    if errors:
        raise RuntimeError(
            f"Subset PCAP/manifest mismatch: {errors[:5]}"
        )

    summary = json.loads(src_summary.read_text(encoding="utf-8"))

    summary["demo_subset"] = {
        "source_run": str(source_dir),
        "selected_flows": len(rows),
        "selected_packets": sum(expected.values()),
        "selection_policy": "Whole TCP flows, equal two-cohort split",
        "packet_budget_is_upper_bound": True,
    }

    (destination / "mawi_dataset_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    selection = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "source_run": str(source_dir),
        "selected_flows": len(rows),
        "selected_packets": sum(expected.values()),
        "cohort_size": len(rows) // 2,
        "flow_indices": [int(r["index"]) for r in rows],
        "slots": [int(r["slot"]) for r in rows],
    }

    (destination / "demo_selection.json").write_text(
        json.dumps(selection, indent=2) + "\n"
    )

    subset_rows = read_manifest(
        destination / "mawi_selected_flow_manifest.csv"
    )

    subset_flows = load_replay(
        destination / "mawi_crossstate_replay.pcap",
        subset_rows,
    )

    actual = sum(map(len, subset_flows.values()))

    if actual != sum(expected.values()):
        raise RuntimeError("Subset replay validator count mismatch.")

    return subset_rows, subset_flows


def save_plot(fig, folder, name):
    import matplotlib.pyplot as plt

    fig.tight_layout()

    fig.savefig(folder / f"{name}.png", dpi=300, bbox_inches="tight")
    fig.savefig(folder / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(folder / f"{name}.svg", bbox_inches="tight")

    plt.close(fig)
    log(f"Figure saved: {name}")


def make_subset_plots(rows, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    folder = outdir / "plots_subset"
    folder.mkdir(exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(
        range(1, len(rows) + 1),
        [int(r["packets"]) for r in rows],
    )
    ax.set_xlabel("Selected flow")
    ax.set_ylabel("Captured TCP packets")
    ax.set_title("MAWI demonstration subset: flow packet counts")

    save_plot(fig, folder, "01_flow_packet_counts")

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.hist(
        [int(r.get("ip_bytes", 0)) for r in rows],
        bins=20,
    )
    ax.set_xlabel("IPv4 bytes per flow")
    ax.set_ylabel("Flow count")
    ax.set_title("MAWI subset byte-volume distribution")

    save_plot(fig, folder, "02_flow_byte_distribution")


def run_simulation(rows, flows, outdir):
    """In-memory simulation; not live datapath evidence."""

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    oracle = {}
    bmv2 = {}
    xdp = {}

    decisions = []
    checkpoints = []

    half = len(rows) // 2
    cohort_a = rows[:half]
    cohort_b = rows[half:]

    def process(target, table, selected, first_only, label):
        sent = 0

        for row in selected:
            seq = flows[row["index"]]
            packets = seq[:1] if first_only else seq[1:]

            for packet in packets:
                expected = int(step(oracle, packet["event"]))
                observed = int(step(table, packet["event"]))

                if expected != observed:
                    raise RuntimeError(
                        f"Simulation mismatch at packet {packet['pkt_id']}"
                    )

                decisions.append({
                    "phase": label,
                    "target": target,
                    "flow_index": row["index"],
                    "packet_id": packet["pkt_id"],
                    "slot": packet["slot"],
                    "expected": "ALLOW" if expected else "DROP",
                    "observed": "ALLOW" if observed else "DROP",
                    "match": True,
                })

                sent += 1

        log(
            f"SIM {label}: {sent:,} packets on {target}; "
            "100% agreement"
        )

    def checkpoint(number, direction, source_name, source,
                   destination_name, destination):
        before = dict(destination)

        changed = sum(
            1 for slot, rec in source.items()
            if before.get(slot) != rec
        )

        changed += sum(
            1 for slot in before
            if slot not in source
        )

        start = time.perf_counter()
        destination.clear()
        destination.update(source)
        elapsed = time.perf_counter() - start

        if source != destination:
            raise RuntimeError(
                f"Simulation checkpoint {number} failed."
            )

        checkpoints.append({
            "checkpoint": number,
            "direction": direction,
            "source": source_name,
            "destination": destination_name,
            "records_before": len(before),
            "records_changed": changed,
            "records_after": len(destination),
            "copy_seconds_in_memory": elapsed,
            "status": "PASS",
        })

        log(
            f"SIM CHECKPOINT {number} {direction}: "
            f"PASS; {len(source)} records copied"
        )

    process(
        "BMv2-sim", bmv2, cohort_a, True, "A_INITIAL_SYN"
    )

    checkpoint(
        1, "BMv2 -> XDP",
        "BMv2-sim", bmv2,
        "XDP-sim", xdp,
    )

    process(
        "XDP-sim", xdp, cohort_a, False,
        "A_REMAINDER_AFTER_MIGRATION"
    )

    checkpoint(
        2, "XDP -> BMv2",
        "XDP-sim", xdp,
        "BMv2-sim", bmv2,
    )

    process(
        "XDP-sim", xdp, cohort_b, True, "B_INITIAL_SYN"
    )

    checkpoint(
        3, "XDP -> BMv2",
        "XDP-sim", xdp,
        "BMv2-sim", bmv2,
    )

    process(
        "BMv2-sim", bmv2, cohort_b, False,
        "B_REMAINDER_AFTER_MIGRATION"
    )

    checkpoint(
        4, "BMv2 -> XDP",
        "BMv2-sim", bmv2,
        "XDP-sim", xdp,
    )

    # Seven state-machine controls.
    used = {int(r["slot"]) for r in rows}

    inside_ip = 0x0A5A0001
    outside_ip = 0xC6336401
    dport = 443
    chosen = None

    for sport in range(40000, 60000):
        probe = Ev(
            inside_ip, sport, outside_ip, dport, 6,
            True, True, False, False, False, 60, 0
        )

        key = tuple(int(v) for v in canon(probe))
        slot = int(slot_of(key))

        if slot not in used:
            chosen = sport
            break

    if chosen is None:
        raise RuntimeError("No free slot for synthetic controls.")

    t0 = max(
        (int(p["ts"]) for seq in flows.values() for p in seq),
        default=0,
    ) + 1000

    controls = [
        (
            "unsolicited_external_ack",
            Ev(outside_ip, dport, inside_ip, chosen, 6,
               False, False, True, False, False, 60, t0),
            0,
        ),
        (
            "inside_syn",
            Ev(inside_ip, chosen, outside_ip, dport, 6,
               True, True, False, False, False, 60, t0+1),
            1,
        ),
        (
            "premature_reverse_ack",
            Ev(outside_ip, dport, inside_ip, chosen, 6,
               False, False, True, False, False, 60, t0+2),
            0,
        ),
        (
            "valid_reverse_synack",
            Ev(outside_ip, dport, inside_ip, chosen, 6,
               False, True, True, False, False, 60, t0+3),
            1,
        ),
        (
            "inside_ack",
            Ev(inside_ip, chosen, outside_ip, dport, 6,
               True, False, True, False, False, 60, t0+4),
            1,
        ),
        (
            "inside_fin",
            Ev(inside_ip, chosen, outside_ip, dport, 6,
               True, False, True, True, False, 60, t0+5),
            1,
        ),
        (
            "packet_after_closed",
            Ev(outside_ip, dport, inside_ip, chosen, 6,
               False, False, True, False, False, 60, t0+6),
            0,
        ),
    ]

    for label, event, expected in controls:
        values = (
            int(step(oracle, event)),
            int(step(bmv2, event)),
            int(step(xdp, event)),
        )

        if values != (expected, expected, expected):
            raise RuntimeError(
                f"Control {label} mismatch: {values}"
            )

        decisions.append({
            "phase": "SYNTHETIC_CONTROLS",
            "target": "reference+simulated targets",
            "flow_index": "synthetic",
            "packet_id": label,
            "slot": int(
                slot_of(tuple(int(v) for v in canon(event)))
            ),
            "expected": "ALLOW" if expected else "DROP",
            "observed": "ALLOW" if values[1] else "DROP",
            "match": True,
        })

    if not (oracle == bmv2 == xdp):
        raise RuntimeError("Simulated state tables are not identical.")

    folder = outdir / "simulation"
    folder.mkdir(exist_ok=False)

    with (folder / "packet_decisions.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f, fieldnames=list(decisions[0].keys())
        )
        writer.writeheader()
        writer.writerows(decisions)

    with (folder / "checkpoint_metrics.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(
            f, fieldnames=list(checkpoints[0].keys())
        )
        writer.writeheader()
        writer.writerows(checkpoints)

    summary = {
        "mode": "in_memory_reference_model_simulation",
        "status": "PASS",
        "selected_real_flows": len(rows),
        "selected_real_mawi_packets": sum(
            len(flows[r["index"]]) for r in rows
        ),
        "synthetic_controls": len(controls),
        "synthetic_control_allow": sum(
            1 for _, _, v in controls if v == 1
        ),
        "synthetic_control_drop": sum(
            1 for _, _, v in controls if v == 0
        ),
        "checkpoints": 4,
        "simulated_final_records": len(oracle),
        "final_tables_equal": oracle == bmv2 == xdp,
        "scope": (
            "In-memory reference-model simulation. "
            "Not independent backend or live datapath evidence."
        ),
    }

    (folder / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    plotdir = folder / "plots"
    plotdir.mkdir()

    phases = [
        "A_INITIAL_SYN",
        "A_REMAINDER_AFTER_MIGRATION",
        "B_INITIAL_SYN",
        "B_REMAINDER_AFTER_MIGRATION",
    ]

    counts = Counter(
        r["phase"] for r in decisions
        if r["phase"] != "SYNTHETIC_CONTROLS"
    )

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(phases, [counts[p] for p in phases])
    ax.set_ylabel("Packets")
    ax.set_title("Simulated MAWI packets by migration phase")
    ax.tick_params(axis="x", rotation=15)
    save_plot(fig, plotdir, "01_packets_by_phase")

    fig, ax = plt.subplots(figsize=(5.8, 4.2))
    ax.bar(
        ["ALLOW", "DROP"],
        [
            summary["synthetic_control_allow"],
            summary["synthetic_control_drop"],
        ],
    )
    ax.set_ylabel("Synthetic controls")
    ax.set_title("Simulated firewall state-machine controls")
    save_plot(fig, plotdir, "02_synthetic_allow_drop")

    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.bar(
        ["BMv2-sim", "XDP-sim", "Reference"],
        [len(bmv2), len(xdp), len(oracle)],
    )
    ax.set_ylabel("State records")
    ax.set_title("Final in-memory state table sizes")
    save_plot(fig, plotdir, "03_final_state_records")

    log(f"SIMULATION = PASS; outputs: {folder}")
    return summary


def live_preflight(rows, outdir):
    if os.geteuid() != 0:
        raise RuntimeError("Live mode requires sudo.")

    folder = outdir / "live_preflight"
    folder.mkdir()

    bp = folder / "bmv2_before.json"
    xp = folder / "xdp_before.json"
    rp = folder / "comparison.json"

    b = sync_state.export_state("bmv2", bp, THRIFT_PORT)
    sync_state.export_state("xdp", xp, THRIFT_PORT)

    comparison = sync_state.compare(bp, xp, rp)

    if not comparison.get("equivalent"):
        raise RuntimeError(
            "BMv2/XDP baseline mismatch. Restore the clean runtime first."
        )

    occupied = {
        int(r["slot"])
        for r in b["records"]
    }

    selected = {
        int(r["slot"])
        for r in rows
    }

    clashes = occupied & selected

    if clashes:
        raise RuntimeError(
            f"{len(clashes)} selected slots are occupied. "
            "Restore the clean isolated runtime before replay."
        )

    log(
        f"LIVE BASELINE PASS: {len(occupied)} records; "
        "selected slots disjoint."
    )


def run_live_subset(subset_dir, rows, outdir, batch_size, delay):
    live_preflight(rows, outdir)

    live_root = outdir / "live_migration"
    live_root.mkdir()

    command = [
        sys.executable,
        str(ROOT / "scripts" / "mawi_crossstate_live_migration.py"),
        "--run-dir", str(subset_dir),
        "--output-dir", str(live_root),
        "--cohort-size", str(len(rows) // 2),
        "--batch-size", str(batch_size),
        "--inter-packet-ms", str(delay),
        "--traffic-quiesced",
    ]

    log("Launching actual BMv2/XDP migration:")
    log(" ".join(command))

    subprocess.run(command, cwd=ROOT, check=True)

    runs = sorted(
        live_root.glob("run_*"),
        key=lambda p: p.stat().st_mtime,
    )

    if not runs:
        raise RuntimeError("No live migration output directory found.")

    run_dir = runs[-1]
    summary_path = run_dir / "mawi_live_migration_summary.json"

    if not summary_path.is_file():
        raise RuntimeError("Live migration summary is missing.")

    summary = json.loads(summary_path.read_text())

    if summary.get("status") != "PASS":
        raise RuntimeError("Live migration did not pass.")

    return run_dir, summary


def run_live_controls(live_run, outdir, batch_size, delay):
    """Seven labelled synthetic cases through both real datapaths."""

    from scapy.all import Ether, IP, TCP, Raw
    import ipaddress

    bpath = live_run / "04_final_bmv2.json"
    xpath = live_run / "04_final_xdp.json"

    if not bpath.is_file() or not xpath.is_file():
        raise RuntimeError("Final live snapshots are missing.")

    btable = snapshot_to_table(json.loads(bpath.read_text()))
    xtable = snapshot_to_table(json.loads(xpath.read_text()))

    if btable != xtable:
        raise RuntimeError("Targets differ before synthetic controls.")

    src_ip = 0xC6120001
    dst_ip = 0xC6120002
    dport = 443

    chosen = None

    for sport in range(40000, 65000):
        probe = Ev(
            src_ip, sport, dst_ip, dport, 6,
            True, True, False, False, False, 40, 0
        )

        key = tuple(int(v) for v in canon(probe))
        slot = int(slot_of(key))

        if slot not in btable:
            chosen = (sport, key, slot)
            break

    if chosen is None:
        raise RuntimeError("Could not allocate a free control slot.")

    sport, key, slot = chosen

    base_ts = max(
        (int(v[2]) for v in btable.values()),
        default=0,
    ) + 1_000_000

    cases = [
        ("unsolicited_external_ack", 0, 0x10, 0),
        ("inside_syn", 1, 0x02, 1),
        ("premature_reverse_ack", 0, 0x10, 0),
        ("valid_reverse_synack", 0, 0x12, 1),
        ("inside_ack", 1, 0x10, 1),
        ("inside_fin", 1, 0x11, 1),
        ("packet_after_closed", 0, 0x10, 0),
    ]

    packets = []

    for i, (label, direction, flags, verdict) in enumerate(cases):
        ts = base_ts + i + 1

        if direction:
            sip, sport_now = src_ip, sport
            dip, dport_now = dst_ip, dport
        else:
            sip, sport_now = dst_ip, dport
            dip, dport_now = src_ip, sport

        event = Ev(
            sip, sport_now, dip, dport_now, 6,
            bool(direction),
            bool(flags & 0x02),
            bool(flags & 0x10),
            bool(flags & 0x01),
            bool(flags & 0x04),
            40, ts,
        )

        ip_bytes = bytes(
            IP(
                src=str(ipaddress.IPv4Address(sip)),
                dst=str(ipaddress.IPv4Address(dip)),
            ) / TCP(
                sport=sport_now,
                dport=dport_now,
                flags=flags,
            )
        )

        pkt_id = 0xF0000000 + i

        shim = (
            ts.to_bytes(6, "big")
            + pkt_id.to_bytes(4, "big")
            + bytes([direction])
            + b"\x08\x00"
        )

        frame = bytes(
            Ether(
                dst="00:00:00:00:00:01",
                src="00:00:00:00:00:02",
                type=0x88B5,
            ) / Raw(load=shim + ip_bytes)
        )

        packets.append({
            "frame": frame,
            "key": key,
            "slot": slot,
            "ts": ts,
            "pkt_id": pkt_id,
            "direction": direction,
            "ip_len": len(ip_bytes),
            "tcp_flags": flags,
            "event": event,
        })

    folder = outdir / "live_controls"
    folder.mkdir()

    decisions = []

    b_oracle = dict(btable)
    x_oracle = dict(xtable)

    log("LIVE CONTROL SEQUENCE: BMv2")

    replay_batch(
        "bmv2", packets, b_oracle, decisions,
        batch_size=batch_size,
        inter_packet_ms=delay,
        phase="SYNTHETIC_CONTROLS",
    )

    log("LIVE CONTROL SEQUENCE: XDP")

    replay_batch(
        "xdp", packets, x_oracle, decisions,
        batch_size=batch_size,
        inter_packet_ms=delay,
        phase="SYNTHETIC_CONTROLS",
    )

    bp = folder / "bmv2_after.json"
    xp = folder / "xdp_after.json"
    rp = folder / "comparison.json"

    sync_state.export_state("bmv2", bp, THRIFT_PORT)
    sync_state.export_state("xdp", xp, THRIFT_PORT)

    comparison = sync_state.compare(bp, xp, rp)

    bfinal = snapshot_to_table(json.loads(bp.read_text()))
    xfinal = snapshot_to_table(json.loads(xp.read_text()))

    if (
        not comparison.get("equivalent")
        or bfinal != xfinal
        or bfinal != b_oracle
        or xfinal != x_oracle
    ):
        raise RuntimeError(
            "Live control sequence caused a state mismatch."
        )

    labels = {
        0xF0000000 + i: case[0]
        for i, case in enumerate(cases)
    }

    fields = [
        "target", "label", "packet_id",
        "expected", "observed", "match",
    ]

    with (folder / "decisions.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for row in decisions:
            writer.writerow({
                "target": row["target"],
                "label": labels[int(row["packet_id"])],
                "packet_id": row["packet_id"],
                "expected": row["expected"],
                "observed": row["observed"],
                "match": row["match"],
            })

    matches = sum(bool(r["match"]) for r in decisions)
    total = len(decisions)

    summary = {
        "status": "PASS" if matches == 14 and comparison.get("equivalent") else "FAIL",
        "packets": total,
        "matches": matches,
        "agreement_percent": 100 * matches / total if total else 0,
        "expected_allow_per_target": sum(c[3] for c in cases),
        "expected_drop_per_target": sum(1 - c[3] for c in cases),
        "final_state_equivalent": bool(comparison.get("equivalent")),
    }

    (folder / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plotdir = folder / "plots"
    plotdir.mkdir()

    for target in ("bmv2", "xdp"):
        target_rows = [
            r for r in decisions
            if r["target"] == target
        ]

        allowed = sum(
            r["expected"] == "ALLOW"
            for r in target_rows
        )

        dropped = sum(
            r["expected"] == "DROP"
            for r in target_rows
        )

        fig, ax = plt.subplots(figsize=(5.8, 4.2))
        ax.bar(["ALLOW", "DROP"], [allowed, dropped])
        ax.set_ylabel("Packets")
        ax.set_title(f"Actual {target.upper()} firewall controls")

        save_plot(fig, plotdir, f"{target}_allow_drop")

    log(
        f"LIVE CONTROLS = {summary['status']}; "
        f"{matches}/{total} decisions matched."
    )

    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--mode",
        choices=["simulate", "live", "both"],
        default="simulate",
    )

    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN)

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/mnt/e/SDN/datasets/mawi/demo_runs"),
    )

    parser.add_argument(
        "--max-packets",
        type=int,
        default=500,
        help="Upper bound; complete TCP flows are never truncated.",
    )

    parser.add_argument(
        "--max-flows",
        type=int,
        default=None,
        help="Optional maximum number of flows; rounded down to an even count.",
    )

    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--inter-packet-ms", type=float, default=0.2)

    args = parser.parse_args()

    if args.max_packets < 1:
        parser.error("--max-packets must be positive")

    if args.max_flows is not None and args.max_flows < 2:
        parser.error("--max-flows must be at least 2")

    if args.batch_size < 1 or args.inter_packet_ms < 0:
        parser.error("Invalid batch size or packet delay.")

    source = args.run_dir.expanduser().resolve()

    manifest_path = source / "mawi_selected_flow_manifest.csv"
    pcap_path = source / "mawi_crossstate_replay.pcap"
    summary_path = source / "mawi_dataset_summary.json"

    for path in (manifest_path, pcap_path, summary_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    rows_all = read_manifest(manifest_path)
    all_flows = load_replay(pcap_path, rows_all)

    total_source = sum(map(len, all_flows.values()))

    log(
        f"VALIDATED SOURCE: {len(rows_all)} flows / "
        f"{total_source:,} packets"
    )

    selected = select_whole_flows(
        rows_all,
        all_flows,
        args.max_packets,
        args.max_flows,
    )

    selected_packets = sum(
        len(all_flows[r["index"]])
        for r in selected
    )

    log(
        f"SELECTED: {len(selected)} whole flows / "
        f"{selected_packets:,} packets; "
        f"budget={args.max_packets}"
    )

    args.output_dir.expanduser().resolve().mkdir(
        parents=True,
        exist_ok=True,
    )

    outdir = (
        args.output_dir.expanduser().resolve()
        / f"demo_{stamp()}"
    )

    outdir.mkdir()

    subset_dir = outdir / "prepared_subset"

    subset_rows, subset_flows = prepare_subset(
        source,
        selected,
        subset_dir,
    )

    make_subset_plots(subset_rows, outdir)

    result = {
        "mode": args.mode,
        "source_run": str(source),
        "selected_flows": len(subset_rows),
        "selected_packets": selected_packets,
        "packet_budget_upper_bound": args.max_packets,
        "demo_directory": str(outdir),
    }

    if args.mode in ("simulate", "both"):
        result["simulation"] = run_simulation(
            subset_rows,
            subset_flows,
            outdir,
        )

    if args.mode in ("live", "both"):
        if os.geteuid() != 0:
            raise RuntimeError(
                "Live mode requires sudo and the CrossState venv PYTHONPATH."
            )

        live_dir, live_summary = run_live_subset(
            subset_dir,
            subset_rows,
            outdir,
            args.batch_size,
            args.inter_packet_ms,
        )

        result["live"] = live_summary

        result["live_controls"] = run_live_controls(
            live_dir,
            outdir,
            args.batch_size,
            args.inter_packet_ms,
        )

    walkthrough = f"""
# CrossState Demo Walkthrough

- Mode: `{args.mode}`
- Source run: `{source}`
- Selected complete flows: **{len(subset_rows)}**
- Actual replay packets: **{selected_packets}**
- Packet budget upper bound: **{args.max_packets}**
- Cohort size: **{len(subset_rows)//2} flows**

## Live migration sequence

1. Show the MAWI-derived TCP subset.
2. Cohort A initial SYN packets go through BMv2.
3. Quiesced checkpoint BMv2 -> XDP.
4. Cohort A remaining packets go through XDP.
5. Quiesced checkpoint XDP -> BMv2.
6. Cohort B initial SYN packets go through XDP.
7. Quiesced checkpoint XDP -> BMv2.
8. Cohort B remaining packets go through BMv2.
9. Quiesced checkpoint BMv2 -> XDP.
10. Verify final BMv2/XDP state and reference decisions.
11. Run seven labelled synthetic ALLOW/DROP controls on both real targets.

## Evidence

- `prepared_subset/`: subset PCAP and manifest.
- `plots_subset/`: MAWI subset plots.
- `simulation/`: simulation CSV, JSON and figures.
- `live_migration/`: live snapshots, decisions, checkpoint metrics and figures.
- `live_controls/`: actual datapath negative-control results and figures.

## Scope

Simulation mode uses the Python reference function for both in-memory
target tables; it is not independent backend validation.

Live mode sends packets through BMv2 and XDP. Migration uses four
quiesced checkpoints, not continuous replication.

MAWI has no firewall trust-boundary labels; captured initiator is
assigned the inside role for this controlled replay.
"""

    (outdir / "DEMO_WALKTHROUGH.md").write_text(walkthrough)

    (outdir / "demo_summary.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )

    log("CROSSSTATE DEMO COMPLETE")
    log(f"Results: {outdir}")
    log(f"Walkthrough: {outdir}/DEMO_WALKTHROUGH.md")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(
            "Interrupted. Inspect datapath state before restarting.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except Exception as exc:
        print(f"CROSSSTATE DEMO FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
