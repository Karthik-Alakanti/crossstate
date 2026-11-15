#!/usr/bin/env python3
"""Publication-oriented analysis of CrossState-prepared MAWI TCP traffic."""

import argparse
import csv
import json
import math
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# Consistent, colorblind-conscious publication palette.
COLORS = {
    "blue": "#2878B5",
    "orange": "#E87524",
    "green": "#31966B",
    "red": "#C74646",
    "purple": "#8064A2",
    "cyan": "#39A6A3",
    "gray": "#68737D",
    "dark": "#263238",
}

STATE_COLORS = [
    COLORS["blue"], COLORS["orange"], COLORS["green"],
    COLORS["red"], COLORS["purple"],
]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.titlesize": 11,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "figure.titlesize": 12,
    "axes.linewidth": 0.8,
    "lines.linewidth": 1.5,
    "grid.linewidth": 0.5,
    "grid.alpha": 0.25,
    "savefig.facecolor": "white",
    "figure.facecolor": "white",
})


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}. The MAWI preprocessing pipeline "
            "must finish before plotting."
        )
    return json.loads(path.read_text())


def load_manifest(path):
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            r["slot"] = int(r["slot"])
            r["key"] = json.loads(r["key"])
            for field in (
                "packets", "forward_packets", "reverse_packets",
                "ip_bytes", "syn_packets", "synack_packets",
                "ack_packets", "fin_packets", "rst_packets",
                "timestamp_regressions",
            ):
                r[field] = int(r[field])
            for field in (
                "terminal_seen", "idle_timeout_boundary",
                "packet_cap_reached",
            ):
                r[field] = r[field].lower() in ("true", "1", "yes")
            r["responder_port"] = int(r["responder_port"])
            r["initiator_port"] = int(r["initiator_port"])
            rows.append(r)
    if not rows:
        raise ValueError("The MAWI flow manifest is empty.")
    return rows


def read_replay_pcap(path):
    """Read prepared Ethernet PCAP and aggregate per-flow packet metrics."""
    aggregates = defaultdict(lambda: {
        "timestamps": [],
        "ip_bytes": 0,
        "packets": 0,
        "forward": 0,
        "reverse": 0,
        "lengths": [],
        "iat_ms": [],
    })

    global_times = []
    global_lengths = []
    global_bytes = Counter()
    global_packets = Counter()
    pcap_count = 0

    with path.open("rb") as f:
        hdr = f.read(24)
        if len(hdr) != 24:
            raise ValueError("Invalid replay PCAP header.")

        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
            b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
            b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
            b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
        }

        if hdr[:4] not in formats:
            raise ValueError("Unsupported replay PCAP timestamp format.")

        endian, divisor = formats[hdr[:4]]
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        if linktype != 1:
            raise ValueError("Replay PCAP is not Ethernet.")

        while True:
            rec = f.read(16)
            if not rec:
                break
            if len(rec) != 16:
                raise ValueError("Truncated PCAP record header.")

            sec, fraction, incl, orig = struct.unpack(
                endian + "IIII", rec
            )
            frame = f.read(incl)
            if len(frame) != incl:
                raise ValueError("Truncated PCAP frame.")

            if len(frame) < 47 or frame[12:14] != b"\x88\xb5":
                continue

            # Ethernet (14) + CrossState shim (13) + IPv4.
            ipoff = 27
            if frame[25:27] != b"\x08\x00":
                continue

            version = frame[ipoff] >> 4
            ihl = (frame[ipoff] & 15) * 4
            if version != 4 or ihl < 20:
                continue
            if frame[ipoff + 9] != 6:
                continue

            total_len = struct.unpack(
                "!H", frame[ipoff + 2:ipoff + 4]
            )[0]
            if total_len < ihl + 20 or len(frame) < ipoff + ihl + 20:
                continue

            src_ip = int.from_bytes(frame[ipoff + 12:ipoff + 16], "big")
            dst_ip = int.from_bytes(frame[ipoff + 16:ipoff + 20], "big")
            tcp = ipoff + ihl
            sport, dport = struct.unpack("!HH", frame[tcp:tcp + 4])

            a = (src_ip, sport)
            b = (dst_ip, dport)
            if ((a[0] << 16) | a[1]) <= ((b[0] << 16) | b[1]):
                key = (a[0], a[1], b[0], b[1], 6)
            else:
                key = (b[0], b[1], a[0], a[1], 6)

            # The manifest stores canonical keys as JSON arrays.
            slot_key = key
            ts = sec + fraction / divisor
            direction = frame[24] & 1
            stats = aggregates[slot_key]
            stats["timestamps"].append(ts)
            stats["ip_bytes"] += total_len
            stats["packets"] += 1
            stats["forward" if direction else "reverse"] += 1
            stats["lengths"].append(total_len)

            pcap_count += 1
            global_times.append(ts)
            global_lengths.append(total_len)
            second = int(ts)
            global_packets[second] += 1
            global_bytes[second] += total_len

    # Inter-arrival intervals within each flow.
    for stats in aggregates.values():
        times = sorted(stats["timestamps"])
        if len(times) > 1:
            stats["iat_ms"] = [
                (times[i] - times[i - 1]) * 1000
                for i in range(1, len(times))
            ]
        stats["duration_s"] = (
            times[-1] - times[0] if len(times) > 1 else 0.0
        )
        stats["timestamps"] = times

    return {
        "flows": aggregates,
        "packet_count": pcap_count,
        "timestamps": global_times,
        "lengths": global_lengths,
        "packets_per_second": global_packets,
        "bytes_per_second": global_bytes,
    }


def canonical_key(row):
    return tuple(int(x) for x in row["key"])


def gini(values):
    x = np.asarray(values, dtype=float)
    x = x[np.isfinite(x)]
    x = x[x >= 0]
    if len(x) == 0 or x.sum() == 0:
        return 0.0
    x = np.sort(x)
    n = len(x)
    return float(
        (2 * np.sum(np.arange(1, n + 1) * x))
        / (n * np.sum(x)) - (n + 1) / n
    )


def ecdf(values):
    x = np.sort(np.asarray(values, dtype=float))
    if len(x) == 0:
        return x, x
    y = np.arange(1, len(x) + 1) / len(x)
    return x, y


def save_figure(fig, outdir, name):
    fig.tight_layout()
    fig.savefig(outdir / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(outdir / f"{name}.svg", bbox_inches="tight")
    fig.savefig(
        outdir / f"{name}.png",
        dpi=600,
        bbox_inches="tight",
    )
    plt.close(fig)
    print(f"Figure saved: {name}", flush=True)


def hist_plot(values, title, xlabel, name, outdir, bins=40, logx=False):
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    values = values[values >= 0]
    if len(values) == 0:
        return

    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    ax.hist(
        values,
        bins=bins,
        color=COLORS["blue"],
        edgecolor="white",
        linewidth=0.35,
        alpha=0.9,
    )
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Number of flows / observations")
    if logx and np.max(values) > 0:
        ax.set_xscale("log")
    ax.grid(axis="y")
    save_figure(fig, outdir, name)


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Specific MAWI preparation run directory.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/mnt/e/SDN/datasets/mawi/processed"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Override plot output directory.",
    )
    args = parser.parse_args()

    if args.run_dir is not None:
        run_dir = args.run_dir.expanduser().resolve()
    else:
        candidates = [
            p for p in args.root.glob("run_*")
            if (
                (p / "mawi_dataset_summary.json").exists()
                and (p / "mawi_selected_flow_manifest.csv").exists()
                and (p / "mawi_crossstate_replay.pcap").exists()
            )
        ]
        if not candidates:
            raise FileNotFoundError(
                "No completed MAWI preparation run found. "
                "Wait for mawi_crossstate_pipeline.py to finish."
            )
        run_dir = max(candidates, key=lambda p: p.stat().st_mtime)

    summary_path = run_dir / "mawi_dataset_summary.json"
    manifest_path = run_dir / "mawi_selected_flow_manifest.csv"
    replay_path = run_dir / "mawi_crossstate_replay.pcap"

    summary = load_json(summary_path)
    manifest = load_manifest(manifest_path)

    outdir = (
        args.output.expanduser().resolve()
        if args.output
        else run_dir / "plots_q1_acm"
    )
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"MAWI run: {run_dir}")
    print(f"Plot destination: {outdir}")
    print("Reading replay PCAP...")

    replay = read_replay_pcap(replay_path)
    flow_map = replay["flows"]

    # Validate exact per-flow consistency between PCAP and manifest.
    metrics = []
    errors = []

    for row in manifest:
        key = canonical_key(row)
        pcap_stats = flow_map.get(key)

        if pcap_stats is None:
            errors.append(f"Manifest flow absent from replay PCAP: {row['slot']}")
            continue

        if pcap_stats["packets"] != row["packets"]:
            errors.append(
                f"Packet count mismatch at slot {row['slot']}: "
                f"manifest={row['packets']} pcap={pcap_stats['packets']}"
            )

        if pcap_stats["ip_bytes"] != row["ip_bytes"]:
            errors.append(
                f"Byte count mismatch at slot {row['slot']}: "
                f"manifest={row['ip_bytes']} pcap={pcap_stats['ip_bytes']}"
            )

        duration = pcap_stats["duration_s"]
        packets = pcap_stats["packets"]
        byte_count = pcap_stats["ip_bytes"]

        metrics.append({
            "slot": row["slot"],
            "initiator_ip": row["initiator_ip"],
            "initiator_port": row["initiator_port"],
            "responder_ip": row["responder_ip"],
            "responder_port": row["responder_port"],
            "packets": packets,
            "forward_packets": pcap_stats["forward"],
            "reverse_packets": pcap_stats["reverse"],
            "ip_bytes": byte_count,
            "duration_s": duration,
            "mean_packet_bytes": byte_count / packets if packets else 0,
            "packet_rate_pps": packets / duration if duration > 0 else 0,
            "directional_imbalance": (
                abs(pcap_stats["forward"] - pcap_stats["reverse"])
                / packets if packets else 0
            ),
            "syn_packets": row["syn_packets"],
            "synack_packets": row["synack_packets"],
            "ack_packets": row["ack_packets"],
            "fin_packets": row["fin_packets"],
            "rst_packets": row["rst_packets"],
            "terminal_seen": row["terminal_seen"],
            "idle_timeout_boundary": row["idle_timeout_boundary"],
            "packet_cap_reached": row["packet_cap_reached"],
            "timestamp_regressions": row["timestamp_regressions"],
            "expected_final_state": row["expected_final_state"],
        })

    if replay["packet_count"] != int(summary["replay_packet_count"]):
        errors.append(
            "Replay packet count differs from summary: "
            f"{replay['packet_count']} vs {summary['replay_packet_count']}"
        )

    if sum(m["packets"] for m in metrics) != replay["packet_count"]:
        errors.append("Manifest packet total differs from replay PCAP total.")

    if errors:
        raise RuntimeError(
            "Input validation failed:\n- " + "\n- ".join(errors[:20])
        )

    print(f"Selected flows: {len(metrics):,}")
    print(f"Replay packets: {replay['packet_count']:,}")
    print(f"Replay IP bytes: {sum(m['ip_bytes'] for m in metrics):,}")
    print("Manifest-PCAP consistency: PASS")

    # Export full per-flow metric table.
    metric_fields = list(metrics[0].keys())
    write_csv(outdir / "mawi_flow_metrics.csv", metrics, metric_fields)

    packet_counts = np.array([m["packets"] for m in metrics], dtype=float)
    byte_counts = np.array([m["ip_bytes"] for m in metrics], dtype=float)
    durations = np.array([m["duration_s"] for m in metrics], dtype=float)
    forward = np.array([m["forward_packets"] for m in metrics], dtype=float)
    reverse = np.array([m["reverse_packets"] for m in metrics], dtype=float)
    rates = np.array([m["packet_rate_pps"] for m in metrics], dtype=float)
    imbalance = np.array(
        [m["directional_imbalance"] for m in metrics], dtype=float
    )
    mean_sizes = np.array(
        [m["mean_packet_bytes"] for m in metrics], dtype=float
    )
    iats = [
        v
        for stats in flow_map.values()
        for v in stats["iat_ms"]
        if v >= 0
    ]

    # 01. Capture/replay workload overview.
    overview_labels = [
        "Captured frames",
        "IPv4/TCP packets",
        "Selected replay packets",
        "Selected TCP flows",
    ]
    overview_values = [
        int(summary["capture_frames_scanned"]),
        int(summary["ipv4_tcp_packets"]),
        int(replay["packet_count"]),
        len(metrics),
    ]

    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    bars = ax.bar(
        overview_labels,
        overview_values,
        color=[COLORS["gray"], COLORS["blue"],
               COLORS["green"], COLORS["orange"]],
    )
    ax.set_yscale("log")
    ax.set_ylabel("Count (log scale)")
    ax.set_title("MAWI Capture and CrossState Replay Workload")
    ax.tick_params(axis="x", rotation=18)
    ax.grid(axis="y")
    for bar, value in zip(bars, overview_values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:,}",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    save_figure(fig, outdir, "01_capture_replay_overview")

    # 02. TCP flags in the complete source capture.
    flags = summary.get("tcp_flag_packet_counts", {})
    flag_names = ["SYN", "SYN_ACK", "ACK", "FIN", "RST"]
    flag_values = [int(flags.get(k, 0)) for k in flag_names]

    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.bar(flag_names, flag_values, color=COLORS["blue"])
    ax.set_ylabel("Packet count")
    ax.set_title("TCP Control-Flag Prevalence in Source Capture")
    ax.set_yscale("log")
    ax.grid(axis="y")
    save_figure(fig, outdir, "02_tcp_flag_prevalence")

    # 03-05. Flow packet-count distribution, ECDF, CCDF.
    hist_plot(
        packet_counts,
        "Per-Flow Packet Count Distribution",
        "Packets per selected flow",
        "03_flow_packet_count_distribution",
        outdir,
        bins=40,
        logx=True,
    )

    x, y = ecdf(packet_counts)
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.step(x, y, where="post", color=COLORS["blue"])
    ax.set_xlabel("Packets per flow")
    ax.set_ylabel("Empirical cumulative probability")
    ax.set_title("Empirical CDF of Per-Flow Packet Counts")
    ax.set_ylim(0, 1.02)
    ax.grid(True)
    save_figure(fig, outdir, "04_flow_packet_count_ecdf")

    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.step(x, 1 - y, where="post", color=COLORS["orange"])
    ax.set_xlabel("Packets per flow")
    ax.set_ylabel("Exceedance probability")
    ax.set_title("Complementary CDF of Per-Flow Packet Counts")
    ax.set_yscale("log")
    ax.set_ylim(bottom=1 / len(y))
    ax.grid(True)
    save_figure(fig, outdir, "05_flow_packet_count_ccdf")

    # 06-07. Flow byte volume.
    hist_plot(
        byte_counts,
        "Per-Flow IP Byte-Volume Distribution",
        "IP bytes per flow",
        "06_flow_byte_volume_distribution",
        outdir,
        bins=40,
        logx=True,
    )

    x, y = ecdf(byte_counts)
    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    ax.step(x, y, where="post", color=COLORS["green"])
    ax.set_xlabel("IP bytes per flow")
    ax.set_ylabel("Empirical cumulative probability")
    ax.set_title("Empirical CDF of Flow Byte Volume")
    ax.set_ylim(0, 1.02)
    ax.grid(True)
    save_figure(fig, outdir, "07_flow_byte_volume_ecdf")

    # 08. Directional packet counts.
    fig, ax = plt.subplots(figsize=(5.8, 5.2))
    ax.scatter(
        forward, reverse,
        s=18, alpha=0.55, color=COLORS["blue"],
        edgecolors="none",
    )
    upper = max(float(max(forward.max(), reverse.max())), 1)
    ax.plot([0, upper], [0, upper], "--", color=COLORS["red"],
            label="Equal direction volume")
    ax.set_xlabel("Initiator-to-responder packets")
    ax.set_ylabel("Responder-to-initiator packets")
    ax.set_title("Bidirectional Packet-Count Balance")
    ax.legend()
    ax.grid(True)
    save_figure(fig, outdir, "08_bidirectional_packet_balance")

    # 09. Directional imbalance distribution.
    hist_plot(
        imbalance,
        "Directional Packet Imbalance Across Flows",
        "Absolute directional imbalance (0–1)",
        "09_directional_packet_imbalance",
        outdir,
        bins=30,
    )

    # 10. Packets versus bytes.
    fig, ax = plt.subplots(figsize=(6.4, 4.8))
    ax.scatter(
        packet_counts, byte_counts,
        s=18, alpha=0.5, color=COLORS["purple"],
        edgecolors="none",
    )
    ax.set_xlabel("Packets per flow")
    ax.set_ylabel("IP bytes per flow")
    ax.set_title("Relationship Between Flow Packet Count and Byte Volume")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, which="both")
    save_figure(fig, outdir, "10_flow_packets_vs_bytes")

    # 11. Mean IP packet size.
    hist_plot(
        mean_sizes,
        "Mean IP Packet Size Per Flow",
        "Mean IP bytes per packet",
        "11_mean_packet_size_distribution",
        outdir,
        bins=35,
    )

    # 12. Most frequent responder ports.
    port_counts = Counter(
        int(r["responder_port"]) for r in metrics
    )
    top_ports = port_counts.most_common(15)

    fig, ax = plt.subplots(figsize=(7.0, 5.2))
    ports = [str(p) for p, _ in top_ports][::-1]
    counts = [c for _, c in top_ports][::-1]
    ax.barh(ports, counts, color=COLORS["cyan"])
    ax.set_xlabel("Selected flow count")
    ax.set_ylabel("Responder TCP port")
    ax.set_title("Most Frequent Responder Ports")
    ax.grid(axis="x")
    save_figure(fig, outdir, "12_responder_port_distribution")

    # 13. Flow termination/censoring categories.
    terminal = sum(m["terminal_seen"] for m in metrics)
    idle = sum(m["idle_timeout_boundary"] for m in metrics)
    cap = sum(m["packet_cap_reached"] for m in metrics)
    other = max(0, len(metrics) - terminal - idle - cap)

    fig, ax = plt.subplots(figsize=(6.5, 4.3))
    labels = ["FIN/RST observed", "Idle timeout", "Packet cap", "Other"]
    vals = [terminal, idle, cap, other]
    bars = ax.bar(
        labels, vals,
        color=[COLORS["green"], COLORS["orange"],
               COLORS["red"], COLORS["gray"]],
    )
    ax.set_ylabel("Flow count")
    ax.set_title("Observed Flow Termination and Censoring")
    ax.tick_params(axis="x", rotation=15)
    ax.grid(axis="y")
    for bar, value in zip(bars, vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            str(value),
            ha="center",
            va="bottom",
        )
    save_figure(fig, outdir, "13_flow_termination_categories")

    # 14-15. Flow duration.
    hist_plot(
        durations,
        "Observed Duration of Selected TCP Sessions",
        "Observed flow duration (seconds)",
        "14_flow_duration_distribution",
        outdir,
        bins=35,
    )

    fig, ax = plt.subplots(figsize=(6.4, 4.8))
    ax.scatter(
        durations, packet_counts,
        s=18, alpha=0.5, color=COLORS["blue"],
        edgecolors="none",
    )
    ax.set_xlabel("Observed flow duration (seconds)")
    ax.set_ylabel("Packets per flow")
    ax.set_title("Flow Duration Versus Packet Activity")
    ax.set_xscale("symlog", linthresh=0.001)
    ax.set_yscale("log")
    ax.grid(True, which="both")
    save_figure(fig, outdir, "15_flow_duration_vs_activity")

    # 16. Within-flow inter-arrival times.
    if iats:
        hist_plot(
            iats,
            "Within-Flow Packet Inter-Arrival Time",
            "Inter-arrival time (ms)",
            "16_within_flow_interarrival_distribution",
            outdir,
            bins=50,
            logx=True,
        )

    # 17-18. Replay packet and byte intensity.
    pps = replay["packets_per_second"]
    bps = replay["bytes_per_second"]

    if pps:
        base_sec = min(pps)
        t = sorted(pps)
        rel_t = [v - base_sec for v in t]

        fig, ax = plt.subplots(figsize=(8.2, 4.2))
        ax.plot(rel_t, [pps[v] for v in t],
                color=COLORS["blue"], linewidth=1)
        ax.set_xlabel("Replay time (seconds from first packet)")
        ax.set_ylabel("Packets per second")
        ax.set_title("Packet Arrival Intensity of Selected MAWI Traffic")
        ax.grid(True)
        save_figure(fig, outdir, "17_packet_arrival_intensity")

        fig, ax = plt.subplots(figsize=(8.2, 4.2))
        ax.plot(rel_t, [bps[v] for v in t],
                color=COLORS["orange"], linewidth=1)
        ax.set_xlabel("Replay time (seconds from first packet)")
        ax.set_ylabel("IP bytes per second")
        ax.set_title("Byte-Volume Intensity of Selected MAWI Traffic")
        ax.grid(True)
        save_figure(fig, outdir, "18_byte_volume_intensity")

    # 19. Packet size distribution.
    hist_plot(
        replay["lengths"],
        "IP Packet-Length Distribution in Selected Traffic",
        "IP packet length (bytes)",
        "19_ip_packet_length_distribution",
        outdir,
        bins=50,
    )

    # 20. Flow byte-volume Lorenz curve and Gini coefficient.
    ordered = np.sort(byte_counts)
    total = ordered.sum()
    if total > 0:
        cumulative = np.insert(np.cumsum(ordered) / total, 0, 0)
        population = np.linspace(0, 1, len(cumulative))
        coefficient = gini(byte_counts)

        fig, ax = plt.subplots(figsize=(5.8, 5.0))
        ax.plot(population, cumulative, color=COLORS["blue"],
                label=f"Observed flows (Gini={coefficient:.3f})")
        ax.plot([0, 1], [0, 1], "--", color=COLORS["red"],
                label="Perfect equality")
        ax.set_xlabel("Cumulative fraction of flows")
        ax.set_ylabel("Cumulative fraction of IP bytes")
        ax.set_title("Flow Byte-Volume Lorenz Curve")
        ax.legend()
        ax.grid(True)
        save_figure(fig, outdir, "20_flow_byte_volume_lorenz")

    # 21. Flow initiation timeline.
    starts = np.array(
        [int(r["syn_timestamp_us"]) for r in manifest],
        dtype=np.int64,
    )
    starts = (starts - starts.min()) / 1_000_000

    fig, ax = plt.subplots(figsize=(8.0, 4.2))
    ax.hist(starts, bins=40, color=COLORS["purple"])
    ax.set_xlabel("Time from first selected SYN (seconds)")
    ax.set_ylabel("Selected flow starts")
    ax.set_title("Temporal Distribution of Selected TCP Flow Initiations")
    ax.grid(axis="y")
    save_figure(fig, outdir, "21_flow_initiation_timeline")

    # 22. Per-flow packet rate.
    valid_rates = rates[np.isfinite(rates) & (rates >= 0)]
    if len(valid_rates):
        hist_plot(
            valid_rates,
            "Per-Flow Packet Processing Activity",
            "Observed packets per second",
            "22_per_flow_packet_rate",
            outdir,
            bins=40,
            logx=True,
        )

    # Export one-second time series.
    ts_rows = []
    if pps:
        base_sec = min(pps)
        for sec in sorted(set(pps) | set(bps)):
            ts_rows.append({
                "relative_second": sec - base_sec,
                "packets": pps.get(sec, 0),
                "ip_bytes": bps.get(sec, 0),
            })
    write_csv(
        outdir / "mawi_timeseries_1s.csv",
        ts_rows,
        ["relative_second", "packets", "ip_bytes"],
    )

    # Port summary.
    port_rows = [
        {"responder_port": port, "flow_count": count}
        for port, count in port_counts.most_common()
    ]
    write_csv(
        outdir / "mawi_service_port_summary.csv",
        port_rows,
        ["responder_port", "flow_count"],
    )

    # LaTeX workload table.
    total_flow_bytes = int(byte_counts.sum())
    tex = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Characteristics of the selected MAWI TCP workload.}",
        r"\label{tab:mawi_workload}",
        r"\begin{tabular}{lr}",
        r"\hline",
        r"Metric & Value \\",
        r"\hline",
        f"Captured frames & {int(summary['capture_frames_scanned']):,} \\\\",
        f"IPv4/TCP packets & {int(summary['ipv4_tcp_packets']):,} \\\\",
        f"Selected TCP flows & {len(metrics):,} \\\\",
        f"Replay packets & {replay['packet_count']:,} \\\\",
        f"Replay IP bytes & {total_flow_bytes:,} \\\\",
        f"Mean packets per flow & {packet_counts.mean():.2f} \\\\",
        f"Median packets per flow & {np.median(packet_counts):.2f} \\\\",
        f"Mean flow duration (s) & {durations.mean():.4f} \\\\",
        f"Byte-volume Gini coefficient & {gini(byte_counts):.4f} \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    (outdir / "mawi_workload_table.tex").write_text(
        "\n".join(tex) + "\n"
    )

    # Reproducibility and validation summary.
    plot_summary = {
        "dataset": summary.get("dataset"),
        "run_directory": str(run_dir),
        "selected_flows": len(metrics),
        "replay_packets": replay["packet_count"],
        "manifest_pcap_packet_consistency": True,
        "manifest_pcap_byte_consistency": True,
        "mean_packets_per_flow": float(packet_counts.mean()),
        "median_packets_per_flow": float(np.median(packet_counts)),
        "mean_flow_duration_seconds": float(durations.mean()),
        "median_flow_duration_seconds": float(np.median(durations)),
        "flow_byte_gini": gini(byte_counts),
        "figures_generated": 22,
        "export_formats": ["PDF", "SVG", "PNG-600-DPI"],
        "note": (
            "These figures characterize the selected MAWI workload. "
            "They are not CrossState migration, latency, throughput, "
            "or scalability measurements."
        ),
    }

    (outdir / "mawi_plot_summary.json").write_text(
        json.dumps(plot_summary, indent=2) + "\n"
    )

    (outdir / "README.txt").write_text(
        "MAWI publication-oriented workload figures\n"
        "===========================================\n"
        "22 figures in PDF, SVG and 600-DPI PNG formats.\n"
        "CSV outputs: mawi_flow_metrics.csv, mawi_timeseries_1s.csv,\n"
        "mawi_service_port_summary.csv.\n"
        "LaTeX table: mawi_workload_table.tex.\n"
        "Validation: mawi_plot_summary.json.\n\n"
        "Figures characterize selected MAWI traffic only. They do not\n"
        "measure CrossState migration performance or hardware throughput.\n"
    )

    print("\n========== MAWI JOURNAL PLOTTING COMPLETE ==========")
    print(f"Figures: {outdir}")
    print("Export formats: PDF, SVG, PNG (600 DPI)")
    print(f"Flows: {len(metrics):,}")
    print(f"Packets: {replay['packet_count']:,}")
    print(f"Byte-volume Gini: {gini(byte_counts):.4f}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nPLOTTING ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
