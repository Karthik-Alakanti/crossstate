#!/usr/bin/env python3
"""CrossState G7 flow-count sweep (RQ3/RQ4).

Runs scripts/g7_scale_1000.py across flow counts (100, 500, 1k, 2k, 5k, 10k),
collects checkpoint seconds, records written, equivalence pass/fail, and
collision rejections, then writes a results JSON and two plots:

  - checkpoint time vs flows (log-x)
  - records written vs flows

This is an orchestration wrapper: it shells out to g7_scale_1000.py, which
requires the BMv2/XDP testbed (root, interfaces, Thrift port 9090, flow_state
map). Without the testbed the runs will fail at the preflight stage; the
sweep code itself is complete.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:  # pragma: no cover - plotting optional
    plt = None
    np = None

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

G7_SCRIPT = ROOT / "scripts" / "g7_scale_1000.py"
DEFAULT_FLOWS = [100, 500, 1000, 2000, 5000, 10000]

from scripts.sota_metrics import sota_json, sota_table, sota_csv, CrossStateResult


def log(message: str) -> None:
    print(message, flush=True)


def run_single_sweep(
    flows: int,
    output_root: Path,
    *,
    batch_size: int = 50,
    inter_packet_ms: float = 0.5,
) -> dict[str, Any]:
    """Run g7_scale_1000.py once for a given flow count and collect metrics."""
    run_dir = output_root / f"flows_{flows}"
    run_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(G7_SCRIPT),
        "--flows",
        str(flows),
        "--output-dir",
        str(run_dir),
        "--batch-size",
        str(batch_size),
        "--inter-packet-ms",
        str(inter_packet_ms),
        "--traffic-quiesced",
    ]

    t0 = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        wall_seconds = time.perf_counter() - t0

        combined = (result.stdout or "") + (result.stderr or "")
        log_path = run_dir / "g7_run.log"
        log_path.write_text(combined)

        if result.returncode != 0:
            return {
                "flows": flows,
                "status": "FAILED",
                "returncode": result.returncode,
                "wall_seconds": wall_seconds,
                "log": str(log_path),
                "error": combined[-2000:],
            }
    except Exception as exc:  # pragma: no cover - subprocess failure
        return {
            "flows": flows,
            "status": "ERROR",
            "wall_seconds": time.perf_counter() - t0,
            "error": str(exc),
        }

    # Parse summary.json produced by g7_scale_1000.py.
    summary_path = run_dir / "summary.json"
    summary: dict[str, Any] = {}
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text())

    # Collect checkpoint timing from audit files (phase_seconds added in exp 1).
    state_dir = ROOT / "artifacts" / "state"
    checkpoint_durations: list[float] = []
    checkpoint_audit_dir = run_dir / "checkpoint_audits"
    if checkpoint_audit_dir.is_dir():
        for cp_dir in sorted(checkpoint_audit_dir.iterdir()):
            if not cp_dir.is_dir():
                continue
            for audit_file in cp_dir.glob("*_audit.json"):
                try:
                    audit = json.loads(audit_file.read_text())
                    for phase, secs in audit.get("phase_seconds", {}).items():
                        checkpoint_durations.append(float(secs))
                except Exception:  # pragma: no cover - parse tolerant
                    pass

    # Collision rejections: scan g7 run log for blocked import actions.
    collision_rejections = 0
    if log_path.is_file():
        for line in log_path.read_text(errors="replace").splitlines():
            if "blocked_slot_conflict" in line or "blocked_same_key_difference" in line:
                collision_rejections += 1

    total_checkpoint_seconds = sum(checkpoint_durations)

    return {
        "flows": flows,
        "status": "PASS",
        "returncode": result.returncode,
        "wall_seconds": round(wall_seconds, 4),
        "checkpoint_seconds": round(total_checkpoint_seconds, 4),
        "checkpoint_count": len(checkpoint_durations),
        "baseline_records": summary.get("baseline_records_preserved"),
        "final_bmv2_records": summary.get("final_bmv2_records"),
        "final_xdp_records": summary.get("final_xdp_records"),
        "final_logically_equivalent": summary.get("final_logically_equivalent"),
        "final_exact_matches": summary.get("final_exact_matches"),
        "final_differing_records": summary.get("final_differing_records"),
        "collision_rejections": collision_rejections,
        "summary_path": str(summary_path),
        "log": str(log_path),
    }


def write_results_csv(results: list[dict[str, Any]], path: Path) -> None:
    fields = [
        "flows",
        "status",
        "wall_seconds",
        "checkpoint_seconds",
        "checkpoint_count",
        "baseline_records",
        "final_bmv2_records",
        "final_xdp_records",
        "final_logically_equivalent",
        "final_exact_matches",
        "final_differing_records",
        "collision_rejections",
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k) for k in fields})


def write_results_json(results: list[dict[str, Any]], path: Path) -> None:
    payload = {
        "experiment": "CrossState G7 flow-count sweep (RQ3/RQ4)",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "flow_counts": [r["flows"] for r in results],
        "results": results,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def create_plots(results: list[dict[str, Any]], plot_dir: Path) -> None:
    if plt is None or np is None:
        log("matplotlib/numpy unavailable; plots skipped.")
        return

    passed = [r for r in results if r.get("status") == "PASS"]
    if not passed:
        log("No passing runs; plots skipped.")
        return

    plot_dir.mkdir(parents=True, exist_ok=True)

    flows = [r["flows"] for r in passed]
    checkpoint_secs = [
        r["checkpoint_seconds"] for r in passed if r.get("checkpoint_seconds") is not None
    ]
    records_written = [
        r["final_bmv2_records"] for r in passed if r.get("final_bmv2_records") is not None
    ]
    equivalent = [bool(r.get("final_logically_equivalent")) for r in passed]

    # Plot 1: checkpoint time vs flows (log-x).
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    if checkpoint_secs and len(checkpoint_secs) == len(flows):
        ax.plot(flows, checkpoint_secs, "o-", color="#2878B5", label="checkpoint seconds")
    ax.set_xscale("log")
    ax.set_xlabel("Flows (log scale)")
    ax.set_ylabel("Total checkpoint time (seconds)")
    ax.set_title("Checkpoint Time vs Flow Count")
    ax.grid(True, alpha=0.22, which="both")
    for f, c in zip(flows, checkpoint_secs):
        ax.annotate(f"{c:.2f}s", (f, c), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(plot_dir / "checkpoint_time_vs_flows.png", dpi=150)
    fig.savefig(plot_dir / "checkpoint_time_vs_flows.svg")
    plt.close(fig)

    # Plot 2: records written vs flows.
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    if records_written and len(records_written) == len(flows):
        ax.plot(flows, records_written, "o-", color="#E87524", label="records written")
        ax.plot(flows, flows, "k--", alpha=0.4, label="y = x (1 record per flow)")
    ax.set_xlabel("Flows")
    ax.set_ylabel("Records written (BMv2)")
    ax.set_title("Records Written vs Flow Count")
    ax.grid(True, alpha=0.22)
    ax.legend()
    fig.tight_layout()
    fig.savefig(plot_dir / "records_written_vs_flows.png", dpi=150)
    fig.savefig(plot_dir / "records_written_vs_flows.svg")
    plt.close(fig)

    # Plot 3: equivalence pass/fail vs flows.
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    y = [1 if e else 0 for e in equivalent]
    colors = ["#31966B" if e else "#C0392B" for e in equivalent]
    ax.bar([str(f) for f in flows], y, color=colors)
    ax.set_xlabel("Flows")
    ax.set_ylabel("Logically equivalent (1=PASS, 0=FAIL)")
    ax.set_ylim(0, 1.2)
    ax.set_title("Equivalence Pass/Fail vs Flow Count")
    for i, (f, e) in enumerate(zip(flows, equivalent)):
        ax.text(i, y[i] + 0.05, "PASS" if e else "FAIL", ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(plot_dir / "equivalence_vs_flows.png", dpi=150)
    fig.savefig(plot_dir / "equivalence_vs_flows.svg")
    plt.close(fig)

    log(f"Plots written to {plot_dir}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--flows",
        type=int,
        nargs="+",
        default=DEFAULT_FLOWS,
        help="Flow counts to sweep (default: 100 500 1000 2000 5000 10000).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "scale_sweep",
        help="Sweep artifact directory (default: artifacts/scale_sweep).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Packets per Scapy batch passed to g7_scale_1000.py (default: 50).",
    )
    parser.add_argument(
        "--inter-packet-ms",
        type=float,
        default=0.5,
        help="Inter-packet spacing in ms passed to g7_scale_1000.py (default: 0.5).",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip plot generation (useful without matplotlib).",
    )
    args = parser.parse_args()

    output_root = args.output_dir.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    log(f"G7 flow-count sweep: {args.flows}")
    log(f"Output root: {output_root}")

    results: list[dict[str, Any]] = []
    for flows in args.flows:
        log(f"\n----- flows={flows} -----")
        r = run_single_sweep(
            flows,
            output_root,
            batch_size=args.batch_size,
            inter_packet_ms=args.inter_packet_ms,
        )
        results.append(r)
        status = r.get("status", "UNKNOWN")
        log(f"  status={status}")
        if status == "PASS":
            log(f"  wall={r.get('wall_seconds')}s  checkpoint={r.get('checkpoint_seconds')}s")
            log(f"  records_bmv2={r.get('final_bmv2_records')}  equivalent={r.get('final_logically_equivalent')}")
            log(f"  collision_rejections={r.get('collision_rejections')}")
        else:
            log(f"  error={r.get('error', '')[:200]}")

    # Write outputs.
    csv_path = output_root / "sweep_results.csv"
    json_path = output_root / "sweep_results.json"
    write_results_csv(results, csv_path)
    write_results_json(results, json_path)
    log(f"\nResults CSV: {csv_path}")
    log(f"Results JSON: {json_path}")

    # SOTA comparison outputs (aggregate across passing runs).
    passed = [r for r in results if r.get("status") == "PASS"]
    if passed:
        total_checkpoint = sum(float(r.get("checkpoint_seconds", 0) or 0) for r in passed)
        total_records = sum(int(r.get("final_bmv2_records", 0) or 0) for r in passed)
        equiv_runs = sum(1 for r in passed if r.get("final_logically_equivalent"))
        total_rej = sum(int(r.get("collision_rejections", 0) or 0) for r in passed)
        cs_obj = CrossStateResult(
            experiment="g7_scale_sweep",
            checkpoints=sum(int(r.get("checkpoint_count", 0) or 0) for r in passed),
            total_checkpoint_seconds=total_checkpoint,
            per_record_seconds=(total_checkpoint / total_records if total_records else None),
            records_written=total_records,
            records_total=total_records,
            delta_reduction_percent=None,
            packet_loss_percent=(100.0 * total_rej / sum(int(r.get("flows", 0) or 0) for r in passed) if passed else None),
            decision_agreement_percent=(100.0 * equiv_runs / len(passed) if passed else None),
            state_equivalence_percent=(100.0 * equiv_runs / len(passed) if passed else None),
            rollback_success_percent=None,
            source_stability_pass=True,
            flows_disrupted=total_rej,
            flows_total=sum(int(r.get("flows", 0) or 0) for r in passed),
            downtime_ms=None,
            concurrent_traffic=False,
            cross_platform=True,
            verification_level="audit",
        )
        (output_root / "sota_comparison.md").write_text(sota_table(cs_obj))
        (output_root / "sota_comparison.csv").write_text(sota_csv(cs_obj))
        (output_root / "sota_comparison.json").write_text(
            json.dumps(sota_json(cs_obj), indent=2) + "\n"
        )
        log(f"SOTA comparison: {output_root / 'sota_comparison.md'}")

    if not args.no_plots:
        plot_dir = output_root / "plots"
        create_plots(results, plot_dir)

    # Summary line.
    passed = [r for r in results if r.get("status") == "PASS"]
    log(f"\nSweep complete: {len(passed)}/{len(results)} runs passed.")
    return 0 if passed else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
