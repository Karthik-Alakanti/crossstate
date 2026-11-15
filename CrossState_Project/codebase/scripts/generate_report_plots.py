#!/usr/bin/env python3
"""
CrossState report plot generator.

Inputs:
  artifacts/state/g6_final_bmv2.json
  artifacts/state/g6_final_xdp.json
  artifacts/state/sync_*_audit.json

Output:
  /mnt/e/SDN/plots  (Windows E:\\SDN\\plots)

Generates descriptive plots from actual exported snapshots and audit files.
Does not modify BMv2, XDP, or firewall state.
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "artifacts" / "state"
DEFAULT_OUTPUT = Path("/mnt/e/SDN/plots")

STATE_NAMES = {
    1: "NEW",
    2: "EST",
    3: "CLOSED",
}

STATE_ORDER = [1, 2, 3]
MAP_CAPACITY = 65536

plt.rcParams.update({
    "figure.figsize": (9, 5.5),
    "figure.dpi": 120,
    "savefig.dpi": 220,
    "font.size": 10,
    "axes.titlesize": 13,
    "axes.labelsize": 10,
})


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate CrossState report plots from snapshots."
    )
    parser.add_argument(
        "--bmv2",
        type=Path,
        default=None,
        help="BMv2 snapshot JSON. Defaults to g6_final_bmv2.json.",
    )
    parser.add_argument(
        "--xdp",
        type=Path,
        default=None,
        help="XDP snapshot JSON. Defaults to g6_final_xdp.json.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=STATE_DIR,
        help="Directory containing checkpoint audit JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output directory; default is /mnt/e/SDN/plots.",
    )
    return parser.parse_args()


def choose_snapshot_pair(args):
    if args.bmv2 is not None or args.xdp is not None:
        if args.bmv2 is None or args.xdp is None:
            raise ValueError("Specify both --bmv2 and --xdp.")
        return args.bmv2, args.xdp

    # Prefer the most recent paired live-demo snapshots, if available.
    candidates = sorted(
        args.state_dir.glob("master_demo_*_bmv2_after.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    for bmv2_path in candidates:
        xdp_name = bmv2_path.name.replace(
            "_bmv2_after.json", "_xdp_after.json"
        )
        xdp_path = bmv2_path.with_name(xdp_name)
        if xdp_path.is_file():
            return bmv2_path, xdp_path

    # Otherwise use the recorded final G6 snapshots.
    return (
        args.state_dir / "g6_final_bmv2.json",
        args.state_dir / "g6_final_xdp.json",
    )


def load_snapshot(path, expected_target):
    path = path.expanduser().resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Snapshot not found: {path}")

    with path.open(encoding="utf-8") as f:
        data = json.load(f)

    if data.get("source_target") != expected_target:
        raise ValueError(
            f"{path.name}: expected source_target={expected_target!r}, "
            f"got {data.get('source_target')!r}"
        )

    records = {}
    for rec in data.get("records", []):
        slot = int(rec["slot"])

        if not 0 <= slot < MAP_CAPACITY:
            raise ValueError(f"Invalid slot number: {slot}")
        if slot in records:
            raise ValueError(f"Duplicate slot in {path.name}: {slot}")

        state = int(rec["st"])
        if state not in STATE_NAMES:
            raise ValueError(f"Invalid TCP state {state} at slot {slot}")

        key = rec["key"]
        if len(key) != 5:
            raise ValueError(f"Invalid flow key at slot {slot}")

        records[slot] = {
            "slot": slot,
            "key": [int(v) for v in key],
            "st": state,
            "last": int(rec["last"]),
            "pkts": int(rec["pkts"]),
            "bytes": int(rec["bytes"]),
        }

    return data, records, path


def logical_equal(a, b):
    fields = ("key", "st", "last", "pkts", "bytes")
    return all(a[k] == b[k] for k in fields)


def compare_records(bmv2, xdp):
    b_slots = set(bmv2)
    x_slots = set(xdp)
    common = b_slots & x_slots

    exact = [s for s in common if logical_equal(bmv2[s], xdp[s])]
    differing = [s for s in common if not logical_equal(bmv2[s], xdp[s])]

    return {
        "bmv2_only": sorted(b_slots - x_slots),
        "xdp_only": sorted(x_slots - b_slots),
        "exact": sorted(exact),
        "differing": sorted(differing),
        "common": sorted(common),
    }


def save_plot(fig, output_dir, filename):
    path = output_dir / filename
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    print(f"  Created: {path}")


def plot_equivalence(output_dir, comparison):
    labels = [
        "Exact matches",
        "Different values",
        "BMv2 only",
        "XDP only",
    ]
    values = [
        len(comparison["exact"]),
        len(comparison["differing"]),
        len(comparison["bmv2_only"]),
        len(comparison["xdp_only"]),
    ]

    fig, ax = plt.subplots()
    bars = ax.bar(labels, values)
    ax.set_title("Cross-target logical state equivalence")
    ax.set_ylabel("Number of flow records")
    ax.tick_params(axis="x", rotation=12)
    ax.set_ylim(bottom=0)

    for bar, value in zip(bars, values):
        ax.annotate(
            str(value),
            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
        )

    save_plot(fig, output_dir, "01_cross_target_equivalence.png")


def plot_state_distribution(output_dir, bmv2, xdp):
    b_counts = Counter(r["st"] for r in bmv2.values())
    x_counts = Counter(r["st"] for r in xdp.values())

    labels = [STATE_NAMES[s] for s in STATE_ORDER]
    b_values = [b_counts[s] for s in STATE_ORDER]
    x_values = [x_counts[s] for s in STATE_ORDER]

    positions = list(range(len(labels)))
    width = 0.36

    fig, ax = plt.subplots()
    ax.bar(
        [p - width / 2 for p in positions],
        b_values,
        width,
        label="BMv2",
    )
    ax.bar(
        [p + width / 2 for p in positions],
        x_values,
        width,
        label="XDP",
    )

    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Number of flows")
    ax.set_title("TCP connection-state distribution")
    ax.legend()
    ax.set_ylim(bottom=0)

    save_plot(fig, output_dir, "02_tcp_state_distribution.png")


def plot_counter_parity(output_dir, bmv2, xdp, common, field, filename, title):
    bx = [bmv2[s][field] for s in common]
    xy = [xdp[s][field] for s in common]

    fig, ax = plt.subplots()
    ax.scatter(bx, xy, alpha=0.75, label="Flows")

    if bx or xy:
        low = min(bx + xy)
        high = max(bx + xy)
        margin = max(1, (high - low) * 0.05)
        lower, upper = low - margin, high + margin
        ax.plot(
            [lower, upper],
            [lower, upper],
            linestyle="--",
            label="Perfect agreement (y = x)",
        )

    ax.set_xlabel(f"BMv2 {field}")
    ax.set_ylabel(f"XDP {field}")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.25)

    save_plot(fig, output_dir, filename)


def plot_slot_distribution(output_dir, bmv2, xdp):
    fig, ax = plt.subplots()
    bins = 16

    ax.hist(
        list(bmv2.keys()),
        bins=bins,
        range=(0, MAP_CAPACITY),
        alpha=0.55,
        label="BMv2",
    )
    ax.hist(
        list(xdp.keys()),
        bins=bins,
        range=(0, MAP_CAPACITY),
        alpha=0.55,
        label="XDP",
    )

    ax.set_title("Occupied CRC32 direct-map slots")
    ax.set_xlabel("Slot index (16 equal ranges across 65,536 slots)")
    ax.set_ylabel("Occupied flow records per range")
    ax.legend()

    save_plot(fig, output_dir, "05_hash_slot_occupancy.png")


def parse_audit_datetime(value):
    if not value:
        return None

    for fmt in ("%Y%m%dT%H%M%S.%fZ", "%Y%m%dT%H%M%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def load_audits(state_dir):
    audits = []

    for path in state_dir.glob("sync_*_audit.json"):
        try:
            with path.open(encoding="utf-8") as f:
                item = json.load(f)

            if not item.get("equivalent"):
                continue
            if not item.get("readiness_marked"):
                continue

            when = parse_audit_datetime(item.get("created_utc"))
            if when is None:
                continue

            direction = item.get("direction", "unknown")
            count = int(item.get("synced_records", item.get("source_records", 0)))

            audits.append({
                "file": path.name,
                "time": when,
                "direction": direction,
                "records": count,
                "equivalent": True,
                "readiness_marked": True,
            })
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            print(f"  Skipping unreadable audit: {path.name}")

    audits.sort(key=lambda item: item["time"])
    return audits


def plot_checkpoint_history(output_dir, audits):
    if not audits:
        print("  No compatible successful checkpoint audits found; skipped.")
        return

    fig, ax = plt.subplots()

    directions = sorted({a["direction"] for a in audits})
    for direction in directions:
        subset = [a for a in audits if a["direction"] == direction]
        ax.plot(
            [a["time"] for a in subset],
            [a["records"] for a in subset],
            marker="o",
            label=direction,
        )

    ax.set_title("Verified checkpoint size over time")
    ax.set_xlabel("Checkpoint audit timestamp")
    ax.set_ylabel("Flow records in verified checkpoint")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d\n%H:%M"))
    ax.legend()
    ax.grid(True, alpha=0.25)

    save_plot(fig, output_dir, "06_checkpoint_history.png")


def write_flow_csv(output_dir, bmv2, xdp, comparison):
    path = output_dir / "crossstate_flow_comparison.csv"
    slots = sorted(set(bmv2) | set(xdp))

    columns = [
        "slot", "endpoint_a_ip", "endpoint_a_port",
        "endpoint_b_ip", "endpoint_b_port", "protocol",
        "state_bmv2", "state_xdp",
        "last_bmv2", "last_xdp",
        "packets_bmv2", "packets_xdp",
        "bytes_bmv2", "bytes_xdp",
        "logical_match",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for slot in slots:
            b = bmv2.get(slot)
            x = xdp.get(slot)
            rec = b or x
            key = rec["key"]

            row = {
                "slot": slot,
                "endpoint_a_ip": str(ipaddress.IPv4Address(key[0])),
                "endpoint_a_port": key[1],
                "endpoint_b_ip": str(ipaddress.IPv4Address(key[2])),
                "endpoint_b_port": key[3],
                "protocol": key[4],
                "logical_match": (
                    logical_equal(b, x) if b is not None and x is not None else False
                ),
            }

            for target, item in (("bmv2", b), ("xdp", x)):
                for field in ("st", "last", "pkts", "bytes"):
                    row[f"{field}_{target}"] = (
                        item[field] if item is not None else ""
                    )

            # Keep the column order descriptive.
            row["state_bmv2"] = row.pop("st_bmv2")
            row["state_xdp"] = row.pop("st_xdp")
            row["last_bmv2"] = row.pop("last_bmv2")
            row["last_xdp"] = row.pop("last_xdp")
            row["packets_bmv2"] = row.pop("pkts_bmv2")
            row["packets_xdp"] = row.pop("pkts_xdp")
            row["bytes_bmv2"] = row.pop("bytes_bmv2")
            row["bytes_xdp"] = row.pop("bytes_xdp")

            writer.writerow(row)

    print(f"  Created: {path}")


def main():
    args = parse_args()

    output_dir = args.output_dir.expanduser()

    # Prevent accidentally writing into an unmounted WSL /mnt/e folder.
    if str(output_dir).startswith("/mnt/e/"):
        if not Path("/mnt/e").is_mount():
            raise SystemExit(
                "ERROR: E: is not mounted in WSL at /mnt/e.\n"
                "Check: ls /mnt/e\n"
                "Then rerun this script."
            )

    output_dir.mkdir(parents=True, exist_ok=True)

    bmv2_path, xdp_path = choose_snapshot_pair(args)

    print("=" * 65)
    print("CROSSSTATE REPORT PLOT GENERATOR")
    print("=" * 65)
    print("BMv2 snapshot:", bmv2_path)
    print("XDP snapshot: ", xdp_path)
    print("Output:       ", output_dir.resolve())

    _, bmv2, bmv2_path = load_snapshot(bmv2_path, "bmv2")
    _, xdp, xdp_path = load_snapshot(xdp_path, "xdp")

    comparison = compare_records(bmv2, xdp)
    common = comparison["common"]

    exact = len(comparison["exact"])
    differing = len(comparison["differing"])
    b_only = len(comparison["bmv2_only"])
    x_only = len(comparison["xdp_only"])

    equivalent = (
        exact == len(bmv2) == len(xdp)
        and differing == 0
        and b_only == 0
        and x_only == 0
    )

    print("\n========== SNAPSHOT VALIDATION ==========")
    print("BMv2 records:", len(bmv2))
    print("XDP records:", len(xdp))
    print("Exact matches:", exact)
    print("Different same-slot records:", differing)
    print("BMv2-only records:", b_only)
    print("XDP-only records:", x_only)
    print("Equivalent:", equivalent)

    print("\n========== GENERATING FIGURES ==========")

    plot_equivalence(output_dir, comparison)
    plot_state_distribution(output_dir, bmv2, xdp)

    plot_counter_parity(
        output_dir, bmv2, xdp, common,
        "pkts",
        "03_packet_counter_parity.png",
        "Per-flow packet counter agreement",
    )

    plot_counter_parity(
        output_dir, bmv2, xdp, common,
        "bytes",
        "04_byte_counter_parity.png",
        "Per-flow byte counter agreement",
    )

    plot_slot_distribution(output_dir, bmv2, xdp)

    audits = load_audits(args.state_dir)
    plot_checkpoint_history(output_dir, audits)

    write_flow_csv(output_dir, bmv2, xdp, comparison)

    audit_csv = output_dir / "checkpoint_audit_history.csv"
    if audits:
        with audit_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "file", "time", "direction", "records",
                    "equivalent", "readiness_marked",
                ],
            )
            writer.writeheader()
            for item in audits:
                writer.writerow({
                    **item,
                    "time": item["time"].isoformat(),
                })
        print(f"  Created: {audit_csv}")

    summary = {
        "bmv2_snapshot": str(bmv2_path),
        "xdp_snapshot": str(xdp_path),
        "output_directory": str(output_dir.resolve()),
        "bmv2_records": len(bmv2),
        "xdp_records": len(xdp),
        "exact_matches": exact,
        "differing_records": differing,
        "bmv2_only": b_only,
        "xdp_only": x_only,
        "logically_equivalent": equivalent,
        "successful_checkpoint_audits": len(audits),
        "map_capacity": MAP_CAPACITY,
        "occupancy_percent": (
            100.0 * len(bmv2) / MAP_CAPACITY if MAP_CAPACITY else 0.0
        ),
        "plots": [
            "01_cross_target_equivalence.png",
            "02_tcp_state_distribution.png",
            "03_packet_counter_parity.png",
            "04_byte_counter_parity.png",
            "05_hash_slot_occupancy.png",
        ] + (["06_checkpoint_history.png"] if audits else []),
        "interpretation_note": (
            "These are descriptive plots of recorded snapshots and audit "
            "history. They are not throughput, latency, scalability, or "
            "migration-duration benchmarks."
        ),
    }

    summary_path = output_dir / "crossstate_plot_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")

    readme = output_dir / "README.txt"
    readme.write_text(
        "CrossState report plots\n"
        "=======================\n\n"
        "01: Exact logical state matches versus differences and missing slots.\n"
        "02: NEW, EST and CLOSED flow counts for BMv2 and XDP.\n"
        "03: Per-flow packet-counter parity between targets.\n"
        "04: Per-flow byte-counter parity between targets.\n"
        "05: Occupied CRC32 slot distribution across the 65,536-slot map.\n"
        "06: Number of flow records represented in successful checkpoint\n"
        "    audits over time (when audit files are available).\n\n"
        "CSV files contain per-flow comparison data and checkpoint audit data.\n"
        "JSON contains the comparison summary.\n\n"
        "IMPORTANT:\n"
        "These plots describe the recorded snapshots and checkpoint history.\n"
        "They do not measure throughput, latency, migration duration, or\n"
        "hardware performance. A checkpoint audit's record count is not the\n"
        "number of records physically changed during that operation.\n"
    )

    print(f"  Created: {summary_path}")
    print(f"  Created: {readme}")

    print("\n========== COMPLETE ==========")
    print("Output directory:", output_dir.resolve())
    print("Logical equivalence:", "PASS" if equivalent else "NOT EQUIVALENT")
    print("Figures generated:", len(summary["plots"]))

    if not equivalent:
        print("WARNING: Snapshot mismatch. Inspect the CSV and summary.")

    print("PLOT_GENERATION_COMPLETE")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"\nPLOT_GENERATION_ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
