#!/usr/bin/env python3
"""Generate publication-quality plots from CrossState G7 scale results."""

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


STATE_NAMES = {
    1: "NEW",
    2: "EST",
    3: "CLOSED",
}

MAP_CAPACITY = 65536


def load_json(path):
    if not path.exists():
        raise FileNotFoundError(f"Required experiment file missing: {path}")
    with path.open() as f:
        return json.load(f)


def load_snapshot(path):
    data = load_json(path)
    if "records" not in data:
        raise ValueError(f"No records array in {path}")
    records = data["records"]

    result = {}
    for rec in records:
        slot = int(rec["slot"])
        if slot in result:
            raise ValueError(f"Duplicate slot {slot} in {path}")
        result[slot] = rec

    return data, result


def logical_tuple(rec):
    return (
        tuple(int(x) for x in rec["key"]),
        int(rec["st"]),
        int(rec["last"]),
        int(rec["pkts"]),
        int(rec["bytes"]),
    )


def compare_snapshots(bmv2, xdp):
    bslots = set(bmv2)
    xslots = set(xdp)
    common = bslots & xslots

    mismatches = [
        slot for slot in common
        if logical_tuple(bmv2[slot]) != logical_tuple(xdp[slot])
    ]

    exact = len(common) - len(mismatches)

    return {
        "bmv2_records": len(bmv2),
        "xdp_records": len(xdp),
        "exact_matches": exact,
        "different_records": len(mismatches),
        "bmv2_only": sorted(bslots - xslots),
        "xdp_only": sorted(xslots - bslots),
        "mismatch_slots": mismatches,
        "equivalent": (
            not mismatches and bslots == xslots
        ),
    }


def read_manifest(path):
    rows = []
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            row["slot"] = int(row["slot"])
            row["group"] = int(row["group"])
            row["key"] = json.loads(row["key"])
            rows.append(row)
    return rows


def save_plot(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {path.name}")


def get_count(run_dir, filename):
    _, records = load_snapshot(run_dir / filename)
    return len(records)


def generate_plots(run_dir, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n========== LOADING G7 EXPERIMENT ==========")

    # Final snapshots
    _, bfinal = load_snapshot(run_dir / "08_final_bmv2.json")
    _, xfinal = load_snapshot(run_dir / "08_final_xdp.json")

    comparison = compare_snapshots(bfinal, xfinal)

    print(f"BMv2 records: {len(bfinal)}")
    print(f"XDP records: {len(xfinal)}")
    print(f"Exact matches: {comparison['exact_matches']}")
    print(f"Differing records: {comparison['different_records']}")
    print(f"Logically equivalent: {comparison['equivalent']}")

    # Original baseline
    _, baseline_b = load_snapshot(run_dir / "00_baseline_bmv2.json")
    _, baseline_x = load_snapshot(run_dir / "00_baseline_xdp.json")

    baseline_comparison = compare_snapshots(baseline_b, baseline_x)

    # Generated flow manifest
    manifest = read_manifest(run_dir / "flow_manifest.csv")
    manifest_by_slot = {row["slot"]: row for row in manifest}

    if len(manifest) != len(manifest_by_slot):
        raise ValueError("Duplicate slots found in flow_manifest.csv")

    # Verify the newly generated flows against final state.
    generated_valid = []
    generated_invalid = []

    for item in manifest:
        slot = item["slot"]
        b = bfinal.get(slot)
        x = xfinal.get(slot)

        valid = (
            b is not None
            and x is not None
            and logical_tuple(b) == logical_tuple(x)
            and int(b["st"]) == 1
            and int(b["pkts"]) == 2
            and int(b["bytes"]) == 80
            and int(b["last"]) == int(item["ack_ts"])
        )

        if valid:
            generated_valid.append(item)
        else:
            generated_invalid.append({
                "slot": slot,
                "creation_target": item["creation_target"],
            })

    generated_by_target = Counter(
        item["creation_target"] for item in manifest
    )
    valid_by_target = Counter(
        item["creation_target"] for item in generated_valid
    )

    # ==========================================================
    # 01. Final cross-target equivalence
    # ==========================================================
    fig, ax = plt.subplots(figsize=(9, 5))

    labels = [
        "BMv2 records",
        "XDP records",
        "Exact matches",
    ]
    values = [
        comparison["bmv2_records"],
        comparison["xdp_records"],
        comparison["exact_matches"],
    ]

    bars = ax.bar(labels, values)

    ax.set_ylabel("Number of flow records")
    ax.set_title("Final Cross-Target Logical State Equivalence")
    ax.set_ylim(0, max(values + [1]) * 1.18)
    ax.grid(axis="y", alpha=0.25)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:,}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    status = "PASS" if comparison["equivalent"] else "MISMATCH"
    ax.text(
        0.98, 0.93,
        f"{status} | Differing: {comparison['different_records']}",
        transform=ax.transAxes,
        ha="right",
        va="top",
        fontsize=10,
    )

    save_plot(
        fig,
        output_dir / "01_final_cross_target_equivalence.png",
    )

    # ==========================================================
    # 02. Stage-wise flow population growth
    # ==========================================================
    stages = [
        (
            "Baseline",
            "00_baseline_bmv2.json",
            "00_baseline_xdp.json",
        ),
        (
            "BMv2 SYN",
            "01_after_bmv2_syn_bmv2.json",
            "01_after_bmv2_syn_xdp.json",
        ),
        (
            "Checkpoint 1",
            "02_after_bmv2_to_xdp_bmv2.json",
            "02_after_bmv2_to_xdp_xdp.json",
        ),
        (
            "XDP ACK",
            "02_after_bmv2_to_xdp_bmv2.json",
            "03_xdp_after_ack_group1.json",
        ),
        (
            "Checkpoint 2",
            "04_after_xdp_to_bmv2_group1_bmv2.json",
            "04_after_xdp_to_bmv2_group1_xdp.json",
        ),
        (
            "XDP SYN",
            "05_after_xdp_syn_group2_bmv2.json",
            "05_after_xdp_syn_group2_xdp.json",
        ),
        (
            "Checkpoint 3",
            "06_after_xdp_to_bmv2_all_bmv2.json",
            "06_after_xdp_to_bmv2_all_xdp.json",
        ),
        (
            "BMv2 ACK",
            "07_bmv2_after_ack_group2.json",
            "06_after_xdp_to_bmv2_all_xdp.json",
        ),
        (
            "Final / CP4",
            "08_final_bmv2.json",
            "08_final_xdp.json",
        ),
    ]

    stage_names = []
    stage_bmv2 = []
    stage_xdp = []

    for name, bf, xf in stages:
        stage_names.append(name)
        stage_bmv2.append(get_count(run_dir, bf))
        stage_xdp.append(get_count(run_dir, xf))

    fig, ax = plt.subplots(figsize=(12, 5.5))
    x = list(range(len(stage_names)))

    ax.plot(
        x, stage_bmv2,
        marker="o",
        linewidth=2,
        label="BMv2",
    )
    ax.plot(
        x, stage_xdp,
        marker="s",
        linewidth=2,
        label="XDP",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(stage_names, rotation=25, ha="right")
    ax.set_ylabel("Valid flow records")
    ax.set_title("CrossState Flow Population Across Experiment Stages")
    ax.grid(alpha=0.25)
    ax.legend()

    save_plot(
        fig,
        output_dir / "02_stagewise_flow_population.png",
    )

    # ==========================================================
    # 03. TCP state distribution
    # ==========================================================
    state_counts_b = Counter(
        STATE_NAMES.get(int(r["st"]), f"OTHER_{r['st']}")
        for r in bfinal.values()
    )
    state_counts_x = Counter(
        STATE_NAMES.get(int(r["st"]), f"OTHER_{r['st']}")
        for r in xfinal.values()
    )

    state_order = ["NEW", "EST", "CLOSED"]
    labels = [
        s for s in state_order
        if s in state_counts_b or s in state_counts_x
    ]

    xpos = list(range(len(labels)))
    width = 0.36

    fig, ax = plt.subplots(figsize=(8, 5))

    bvals = [state_counts_b[s] for s in labels]
    xvals = [state_counts_x[s] for s in labels]

    bars_b = ax.bar(
        [p - width / 2 for p in xpos],
        bvals,
        width,
        label="BMv2",
    )
    bars_x = ax.bar(
        [p + width / 2 for p in xpos],
        xvals,
        width,
        label="XDP",
    )

    ax.set_xticks(xpos)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Number of flows")
    ax.set_title("TCP Connection-State Distribution")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()

    for bars in (bars_b, bars_x):
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{int(bar.get_height())}",
                ha="center",
                va="bottom",
                fontsize=9,
            )

    save_plot(
        fig,
        output_dir / "03_tcp_state_distribution.png",
    )

    # ==========================================================
    # 04 and 05. Packet and byte counter parity
    # ==========================================================
    common_slots = sorted(set(bfinal) & set(xfinal))

    packet_b = [int(bfinal[s]["pkts"]) for s in common_slots]
    packet_x = [int(xfinal[s]["pkts"]) for s in common_slots]

    byte_b = [int(bfinal[s]["bytes"]) for s in common_slots]
    byte_x = [int(xfinal[s]["bytes"]) for s in common_slots]

    def parity_plot(a, b, title, xlabel, filename):
        fig, ax = plt.subplots(figsize=(6.5, 6))

        ax.scatter(
            a, b,
            s=18,
            alpha=0.38,
            label=f"{len(a)} flow records",
        )

        upper = max(a + b + [1])
        ax.plot(
            [0, upper],
            [0, upper],
            linestyle="--",
            linewidth=1.5,
            label="Ideal equality (y = x)",
        )

        ax.set_xlim(0, upper * 1.05)
        ax.set_ylim(0, upper * 1.05)
        ax.set_xlabel(f"BMv2 {xlabel}")
        ax.set_ylabel(f"XDP {xlabel}")
        ax.set_title(title)
        ax.grid(alpha=0.25)
        ax.legend()

        save_plot(fig, output_dir / filename)

    parity_plot(
        packet_b,
        packet_x,
        "Per-Flow Packet Counter Agreement",
        "packet count",
        "04_packet_counter_parity.png",
    )

    parity_plot(
        byte_b,
        byte_x,
        "Per-Flow Byte Counter Agreement",
        "byte count",
        "05_byte_counter_parity.png",
    )

    # ==========================================================
    # 06. Hash slot distribution and occupancy
    # ==========================================================
    occupied_slots = sorted(bfinal)
    occupancy = len(occupied_slots) / MAP_CAPACITY * 100

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.hist(
        occupied_slots,
        bins=64,
        range=(0, MAP_CAPACITY),
    )

    ax.set_xlabel("Direct-map slot index")
    ax.set_ylabel("Occupied flow records per interval")
    ax.set_title("Observed Flow Distribution Across the 65,536-Slot Map")
    ax.grid(axis="y", alpha=0.25)

    ax.text(
        0.98, 0.94,
        f"Occupied slots: {len(occupied_slots):,}\n"
        f"Capacity: {MAP_CAPACITY:,}\n"
        f"Occupancy: {occupancy:.4f}%",
        transform=ax.transAxes,
        ha="right",
        va="top",
    )

    save_plot(
        fig,
        output_dir / "06_hash_slot_distribution.png",
    )

    # ==========================================================
    # 07. Generated flow validation
    # ==========================================================
    targets = ["bmv2", "xdp"]

    expected_counts = [
        generated_by_target[t] for t in targets
    ]
    valid_counts = [
        valid_by_target[t] for t in targets
    ]

    xpos = list(range(len(targets)))
    width = 0.34

    fig, ax = plt.subplots(figsize=(8, 5))

    bars_expected = ax.bar(
        [p - width / 2 for p in xpos],
        expected_counts,
        width,
        label="Generated",
    )
    bars_valid = ax.bar(
        [p + width / 2 for p in xpos],
        valid_counts,
        width,
        label="Validated final state",
    )

    ax.set_xticks(xpos)
    ax.set_xticklabels(["BMv2-created flows", "XDP-created flows"])
    ax.set_ylabel("Number of flows")
    ax.set_title("Validation of the 1,000 Newly Generated Flows")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()

    for bars in (bars_expected, bars_valid):
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                str(int(bar.get_height())),
                ha="center",
                va="bottom",
            )

    save_plot(
        fig,
        output_dir / "07_generated_flow_validation.png",
    )

    # ==========================================================
    # 08. Checkpoint transfer operations
    # ==========================================================
    checkpoint_files = [
        (
            "CP1\nBMv2 → XDP",
            "checkpoint_1_bmv2-to-xdp.log",
        ),
        (
            "CP2\nXDP → BMv2",
            "checkpoint_2_xdp-to-bmv2.log",
        ),
        (
            "CP3\nXDP → BMv2",
            "checkpoint_3_xdp-to-bmv2.log",
        ),
        (
            "CP4\nBMv2 → XDP",
            "checkpoint_4_bmv2-to-xdp.log",
        ),
    ]

    transfer_labels = []
    transfer_counts = []
    transfer_types = []

    for label, filename in checkpoint_files:
        path = run_dir / filename
        if not path.exists():
            continue

        content = path.read_text(errors="replace")

        inserts = [
            int(n) for n in re.findall(
                r"\binsert\s*:\s*(\d+)",
                content,
                flags=re.IGNORECASE,
            )
        ]
        replaces = [
            int(n) for n in re.findall(
                r"\breplace\s*:\s*(\d+)",
                content,
                flags=re.IGNORECASE,
            )
        ]

        insert_count = max(inserts, default=0)
        replace_count = max(replaces, default=0)

        transfer_labels.append(label)
        transfer_counts.append(insert_count + replace_count)
        transfer_types.append(
            f"Insert: {insert_count}\nReplace: {replace_count}"
        )

    if transfer_labels:
        fig, ax = plt.subplots(figsize=(9, 5))

        bars = ax.bar(
            list(range(len(transfer_labels))),
            transfer_counts,
        )

        ax.set_xticks(list(range(len(transfer_labels))))
        ax.set_xticklabels(transfer_labels)
        ax.set_ylabel("Records inserted or replaced")
        ax.set_title("Records Transferred During Checkpoint Operations")
        ax.grid(axis="y", alpha=0.25)

        for bar, annotation in zip(bars, transfer_types):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                annotation,
                ha="center",
                va="bottom",
                fontsize=8,
            )

        save_plot(
            fig,
            output_dir / "08_checkpoint_transfer_history.png",
        )
    else:
        print("Checkpoint logs unavailable; skipping figure 08.")

    # ==========================================================
    # Consolidated per-flow CSV
    # ==========================================================
    comparison_csv = output_dir / "g7_flow_state_comparison.csv"

    fields = [
        "slot",
        "key",
        "origin",
        "state_bmv2",
        "state_xdp",
        "last_bmv2",
        "last_xdp",
        "packets_bmv2",
        "packets_xdp",
        "bytes_bmv2",
        "bytes_xdp",
        "logical_match",
    ]

    with comparison_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for slot in common_slots:
            b = bfinal[slot]
            x = xfinal[slot]
            manifest_row = manifest_by_slot.get(slot)

            writer.writerow({
                "slot": slot,
                "key": json.dumps(b["key"]),
                "origin": (
                    manifest_row["creation_target"]
                    if manifest_row else "baseline"
                ),
                "state_bmv2": STATE_NAMES.get(
                    int(b["st"]), str(b["st"])
                ),
                "state_xdp": STATE_NAMES.get(
                    int(x["st"]), str(x["st"])
                ),
                "last_bmv2": b["last"],
                "last_xdp": x["last"],
                "packets_bmv2": b["pkts"],
                "packets_xdp": x["pkts"],
                "bytes_bmv2": b["bytes"],
                "bytes_xdp": x["bytes"],
                "logical_match": (
                    logical_tuple(b) == logical_tuple(x)
                ),
            })

    # ==========================================================
    # Validation summary and README
    # ==========================================================
    all_generated_valid = len(generated_invalid) == 0
    success = (
        comparison["equivalent"]
        and len(manifest) == 1000
        and len(generated_valid) == 1000
        and baseline_comparison["equivalent"]
    )

    summary = {
        "experiment": "CrossState G7 1000-flow scale test",
        "run_directory": str(run_dir),
        "plot_directory": str(output_dir),
        "baseline_bmv2_records": len(baseline_b),
        "baseline_xdp_records": len(baseline_x),
        "baseline_equivalent": baseline_comparison["equivalent"],
        "final_bmv2_records": len(bfinal),
        "final_xdp_records": len(xfinal),
        "final_exact_matches": comparison["exact_matches"],
        "final_differing_records": comparison["different_records"],
        "bmv2_only_slots": len(comparison["bmv2_only"]),
        "xdp_only_slots": len(comparison["xdp_only"]),
        "final_equivalent": comparison["equivalent"],
        "generated_flows": len(manifest),
        "generated_by_target": dict(generated_by_target),
        "generated_valid_by_target": dict(valid_by_target),
        "generated_invalid": len(generated_invalid),
        "all_generated_flows_valid": all_generated_valid,
        "map_capacity": MAP_CAPACITY,
        "occupied_slots": len(occupied_slots),
        "occupancy_percent": occupancy,
        "overall_plot_validation": "PASS" if success else "CHECK",
        "interpretation": (
            "These figures show state correctness, flow population, "
            "counter parity, occupancy and checkpoint record operations. "
            "They do not measure throughput, latency, line rate, "
            "or migration duration."
        ),
    }

    (output_dir / "g7_plot_validation_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    readme = """CrossState G7 Plot Outputs

01_final_cross_target_equivalence.png
02_stagewise_flow_population.png
03_tcp_state_distribution.png
04_packet_counter_parity.png
05_byte_counter_parity.png
06_hash_slot_distribution.png
07_generated_flow_validation.png
08_checkpoint_transfer_history.png

g7_flow_state_comparison.csv
g7_plot_validation_summary.json

All plots are derived from the G7 run snapshots and manifest.
These are correctness and state-distribution plots, not performance
benchmarks. No throughput, latency, line-rate, or migration-duration
claims should be inferred from these figures.
"""

    (output_dir / "README.txt").write_text(readme)

    print("\n========== PLOT VALIDATION ==========")
    print(json.dumps(summary, indent=2))
    print(f"\nPlots and CSV saved to:\n{output_dir}")

    return 0 if success else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Exact G7 run directory. Defaults to newest successful run.",
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/mnt/e/SDN/scale_1000"),
        help="Directory containing run_* folders.",
    )

    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("/mnt/e/SDN/plots/scale_1000"),
        help="Parent directory for plot outputs.",
    )

    args = parser.parse_args()

    if args.run_dir:
        run_dir = args.run_dir.expanduser().resolve()
    else:
        candidates = [
            p for p in args.root.expanduser().glob("run_*")
            if (
                (p / "08_final_bmv2.json").exists()
                and (p / "08_final_xdp.json").exists()
                and (p / "flow_manifest.csv").exists()
            )
        ]

        if not candidates:
            raise FileNotFoundError(
                f"No completed G7 run found under {args.root}"
            )

        run_dir = max(candidates, key=lambda p: p.stat().st_mtime)

    if not run_dir.exists():
        raise FileNotFoundError(run_dir)

    output_dir = (
        args.output_root.expanduser().resolve() / run_dir.name
    )

    print(f"Selected G7 run: {run_dir}")
    print(f"Plot output: {output_dir}")

    return generate_plots(run_dir, output_dir)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"\nPLOTTING FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
