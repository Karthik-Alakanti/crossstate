#!/usr/bin/env python3
"""Standalone SOTA comparison table generator.

Aggregates CrossState experiment outputs (summary JSONs with sota_comparison
blocks) and emits a unified side-by-side SOTA comparison table in markdown,
CSV, and JSON.

Usage:
    python3 scripts/sota_compare.py \
        --summary artifacts/mawi_live_migration/*/mawi_live_migration_summary.json \
        --summary artifacts/scale_sweep/*/sweep_results.json \
        --output artifacts/sota_comparison

Or point it at a directory containing experiment subdirectories:
    python3 scripts/sota_compare.py --artifacts-dir artifacts --output artifacts/sota_comparison
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.sota_metrics import (
    sota_json, sota_table, sota_csv, CrossStateResult, SOTA_REFERENCES,
)


def _extract_cs_result(summary: dict[str, Any]) -> CrossStateResult | None:
    """Extract a CrossStateResult from a summary JSON's sota_comparison block."""
    sota = summary.get("sota_comparison")
    if not sota:
        return None
    cs = sota.get("crossstate")
    if not cs:
        return None
    return CrossStateResult(
        experiment=cs.get("experiment", "unknown"),
        checkpoints=cs.get("checkpoints", 0),
        total_checkpoint_seconds=cs.get("total_checkpoint_seconds", 0.0),
        per_record_seconds=cs.get("per_record_seconds"),
        records_written=cs.get("records_written", 0),
        records_total=cs.get("records_total", 0),
        delta_reduction_percent=cs.get("delta_reduction_percent"),
        packet_loss_percent=cs.get("packet_loss_percent"),
        decision_agreement_percent=cs.get("decision_agreement_percent"),
        state_equivalence_percent=cs.get("state_equivalence_percent"),
        rollback_success_percent=cs.get("rollback_success_percent"),
        source_stability_pass=cs.get("source_stability_pass", False),
        flows_disrupted=cs.get("flows_disrupted", 0),
        flows_total=cs.get("flows_total", 0),
        downtime_ms=cs.get("downtime_ms"),
        concurrent_traffic=cs.get("concurrent_traffic", False),
        cross_platform=cs.get("cross_platform", False),
        verification_level=cs.get("verification_level", "none"),
    )


def find_summaries(artifacts_dir: Path) -> list[Path]:
    """Recursively find summary JSON files with sota_comparison blocks."""
    found: list[Path] = []
    for path in artifacts_dir.rglob("*summary*.json"):
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        if data.get("sota_comparison"):
            found.append(path)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate unified SOTA comparison table from CrossState experiments."
    )
    parser.add_argument(
        "--summary",
        type=Path,
        nargs="+",
        help="Specific summary JSON files with sota_comparison blocks.",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=ROOT / "artifacts",
        help="Directory to scan for experiment summaries (default: artifacts/).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "sota_comparison",
        help="Output directory for comparison table files.",
    )
    args = parser.parse_args()

    summary_paths: list[Path] = []
    if args.summary:
        summary_paths.extend(args.summary)
    if args.artifacts_dir:
        summary_paths.extend(find_summaries(args.artifacts_dir))

    # Deduplicate while preserving order.
    seen = set()
    unique_paths: list[Path] = []
    for p in summary_paths:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            unique_paths.append(rp)

    results: list[CrossStateResult] = []
    for p in unique_paths:
        try:
            data = json.loads(p.read_text())
            cs = _extract_cs_result(data)
            if cs:
                results.append(cs)
        except Exception as exc:
            print(f"WARNING: could not read {p}: {exc}", file=sys.stderr)

    if not results:
        print("No CrossState summaries with sota_comparison blocks found.", file=sys.stderr)
        print("Run an experiment first (e.g. mawi_crossstate_live_migration.py).", file=sys.stderr)
        return 1

    # Use the most complete result as the primary CrossState row (prefer MAWI migration).
    primary = None
    for r in results:
        if r.experiment == "mawi_live_migration":
            primary = r
            break
    if primary is None:
        primary = results[0]

    args.output.mkdir(parents=True, exist_ok=True)

    # Write unified outputs.
    (args.output / "sota_comparison.md").write_text(sota_table(primary))
    (args.output / "sota_comparison.csv").write_text(sota_csv(primary))
    (args.output / "sota_comparison.json").write_text(
        json.dumps(sota_json(primary), indent=2) + "\n"
    )

    # Also write an aggregate of all experiments.
    aggregate = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "experiments": [
            {
                "source": str(p),
                "experiment": r.experiment,
                "checkpoints": r.checkpoints,
                "total_checkpoint_seconds": r.total_checkpoint_seconds,
                "per_record_seconds": r.per_record_seconds,
                "records_written": r.records_written,
                "packet_loss_percent": r.packet_loss_percent,
                "decision_agreement_percent": r.decision_agreement_percent,
                "state_equivalence_percent": r.state_equivalence_percent,
                "rollback_success_percent": r.rollback_success_percent,
                "flows_disrupted": r.flows_disrupted,
                "flows_total": r.flows_total,
                "downtime_ms": r.downtime_ms,
                "verification_level": r.verification_level,
            }
            for p, r in zip(unique_paths, results)
        ],
        "sota_references": {k: v.__dict__ for k, v in SOTA_REFERENCES.items()},
    }
    (args.output / "aggregate.json").write_text(json.dumps(aggregate, indent=2) + "\n")

    print(f"SOTA comparison written to {args.output}/")
    print(f"  sota_comparison.md  (primary: {primary.experiment})")
    print(f"  sota_comparison.csv")
    print(f"  sota_comparison.json")
    print(f"  aggregate.json      ({len(results)} experiments)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
