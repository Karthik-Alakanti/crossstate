#!/usr/bin/env python3
"""SOTA (state-of-the-art) comparison metrics for CrossState.

Defines reference values for related state-migration architectures and
helper functions to emit side-by-side comparison tables against CrossState
experiment results.

SOTA reference values are drawn from the cited literature in
report/crossstate_report_v2.tex (Section: Background and Related Work).
Where a paper reports a qualitative guarantee rather than a number, the
entry is marked ``qualitative`` and the comparison notes the gap.

Reference architectures:
  - OpenNF (SIGCOMM 2014): coordinated move; loss-free, order-preserving.
    Software NFs; coordinates state movement with forwarding changes.
  - Swing State (SOSR 2017): in-band state transfer; consistent updates.
    P4 switches; moves register state between switches.
  - RedPlane (SIGCOMM 2021): replicated state store; fault tolerance.
    Tofino switches; replicated state with recovery.
  - Cora (arXiv 2024): flow-migration protocol; consistency.
    SmartNIC <-> CPU hybrid; offloads stateful apps to SmartNICs.
  - SwitchNIC (CoNEXT 2025): consistent shared state.
    Switch + server hybrid; maintains consistent shared state.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# ---------------------------------------------------------------------------
# SOTA reference values (qualitative where the paper gives no number)
# ---------------------------------------------------------------------------

@dataclass
class SotaReference:
    """One related-work architecture with its characteristics."""

    name: str
    year: int
    platform: str
    mechanism: str
    guarantee: str
    # Quantitative fields (None = not reported in the paper / qualitative)
    downtime_ms: float | None = None
    state_transfer_records: int | None = None
    migration_throughput_rps: float | None = None
    packet_loss_percent: float | None = None
    decision_agreement_percent: float | None = None
    state_equivalence_percent: float | None = None
    rollback_success_percent: float | None = None
    per_record_ms: float | None = None
    concurrent_traffic: bool | None = None
    cross_platform: bool | None = None
    verification_level: str | None = None  # none / read_back / full_equivalence / audit


SOTA_REFERENCES: dict[str, SotaReference] = {
    "RedPlane": SotaReference(
        name="RedPlane",
        year=2021,
        platform="Tofino switches",
        mechanism="replicated state store + external DRAM (lease-based)",
        guarantee="fault tolerance",
        downtime_ms=950.0,
        state_transfer_records=None,
        migration_throughput_rps=None,
        packet_loss_percent=None,
        decision_agreement_percent=None,
        state_equivalence_percent=None,
        rollback_success_percent=None,
        per_record_ms=None,
        concurrent_traffic=True,
        cross_platform=False,
        verification_level="replication",
    ),
    "Cora/Vela": SotaReference(
        name="Cora/Vela",
        year=2024,
        platform="SoC SmartNIC <-> host/Arm CPU",
        mechanism="model-driven compile-time/runtime co-design",
        guarantee="consistency",
        downtime_ms=None,
        state_transfer_records=None,
        migration_throughput_rps=None,
        packet_loss_percent=None,
        decision_agreement_percent=None,
        state_equivalence_percent=None,
        rollback_success_percent=None,
        per_record_ms=None,
        concurrent_traffic=True,
        cross_platform=True,
        verification_level="none",
    ),
    "SwitchNIC": SotaReference(
        name="SwitchNIC",
        year=2025,
        platform="Tofino switch + ARM SmartNIC",
        mechanism="on-path state replication protocol",
        guarantee="strong consistency",
        downtime_ms=None,
        state_transfer_records=None,
        migration_throughput_rps=None,
        packet_loss_percent=None,
        decision_agreement_percent=None,
        state_equivalence_percent=None,
        rollback_success_percent=None,
        per_record_ms=None,
        concurrent_traffic=True,
        cross_platform=True,
        verification_level="none",
    ),
}


# ---------------------------------------------------------------------------
# CrossState measured values (filled in from experiment results)
# ---------------------------------------------------------------------------

@dataclass
class CrossStateResult:
    """CrossState experiment result, populated at runtime."""

    experiment: str
    checkpoints: int
    total_checkpoint_seconds: float
    per_record_seconds: float | None
    records_written: int
    records_total: int
    delta_reduction_percent: float | None
    packet_loss_percent: float
    decision_agreement_percent: float
    state_equivalence_percent: float
    rollback_success_percent: float | None
    source_stability_pass: bool
    flows_disrupted: int
    flows_total: int
    downtime_ms: float | None
    concurrent_traffic: bool = False
    cross_platform: bool = True
    verification_level: str = "audit"


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def sota_table(crossstate: CrossStateResult) -> str:
    """Render a markdown side-by-side comparison table."""
    lines = []
    lines.append("# SOTA Comparison: CrossState vs Related Work")
    lines.append("")
    lines.append(
        "| System | Year | Platform | Downtime (ms) | Records written | "
        "Throughput (rec/s) | Packet loss (%) | Decision agreement (%) | "
        "State equivalence (%) | Rollback (%) | Per-record (ms) | Concurrent | "
        "Cross-platform | Verification |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    )

    # CrossState row first.
    cs = crossstate
    lines.append(
        f"| CrossState | 2026 | BMv2 (P4) <-> XDP (eBPF) | "
        f"{_fmt(cs.downtime_ms)} | {cs.records_written} | "
        f"{_fmt(cs.records_written / cs.total_checkpoint_seconds if cs.total_checkpoint_seconds else None)} | "
        f"{_fmt(cs.packet_loss_percent)} | {_fmt(cs.decision_agreement_percent)} | "
        f"{_fmt(cs.state_equivalence_percent)} | {_fmt(cs.rollback_success_percent)} | "
        f"{_fmt(cs.per_record_seconds)} | {_fmt(cs.concurrent_traffic)} | "
        f"{_fmt(cs.cross_platform)} | {cs.verification_level} |"
    )

    for ref in SOTA_REFERENCES.values():
        lines.append(
            f"| {ref.name} | {ref.year} | {ref.platform} | {_fmt(ref.downtime_ms)} | "
            f"{_fmt(ref.state_transfer_records)} | {_fmt(ref.migration_throughput_rps)} | "
            f"{_fmt(ref.packet_loss_percent)} | {_fmt(ref.decision_agreement_percent)} | "
            f"{_fmt(ref.state_equivalence_percent)} | {_fmt(ref.rollback_success_percent)} | "
            f"{_fmt(ref.per_record_ms)} | {_fmt(ref.concurrent_traffic)} | "
            f"{_fmt(ref.cross_platform)} | {ref.verification_level} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("- Downtime: traffic interruption during migration (quiesced window).")
    lines.append("- Records written: state records transferred per migration cycle.")
    lines.append("- Throughput: records written per second of migration wall time.")
    lines.append("- Packet loss: follow-up packets dropped due to missing state.")
    lines.append("- Decision agreement: datapath decisions matching reference model.")
    lines.append("- State equivalence: source/destination tables identical after migration.")
    lines.append("- Rollback: successful rollback rate on failed imports.")
    lines.append("- Per-record: wall time spent writing one state record.")
    lines.append("- Concurrent: supports migration while traffic flows.")
    lines.append("- Cross-platform: works across heterogeneous targets (P4 <-> eBPF).")
    lines.append("- Verification: none / read_back / full_equivalence / audit.")
    lines.append("")
    lines.append("## Paper-Specific Measured Metrics (not in table above)")
    lines.append("")
    lines.append("| Paper | Key Metrics |")
    lines.append("|-------|-------------|")
    lines.append(
        "| RedPlane (SIGCOMM'21) | "
        "Recovery: 0.9-1.0s after switch failure; "
        "Per-packet overhead: <8µs (write-centric), negligible (read-centric); "
        "ASIC resources: <14%; "
        "Verification: TLA+ model-checked lease protocol |"
    )
    lines.append(
        "| Cora/Vela (arXiv'24) | "
        "CPU savings: 62.9%-91.9% vs best baseline; "
        "Throughput improvement: 15.2%-120.8% (NATLB); "
        "Lock contention: 5-10x performance variation for similar memory ops; "
        "Verification: none (compiler optimization) |"
    )
    lines.append(
        "| SwitchNIC (CoNEXT'25) | "
        "P99 latency: 6µs; Fast-path: ~350ns; "
        "Energy efficiency: 5.2× better than server-based; "
        "Processing latency: 6.4× better than server-based; "
        "Traffic churn: 100k new flows/min tolerated; "
        "Verification: none (strong consistency via on-path replication) |"
    )
    lines.append("")
    lines.append(
        "n/a = not reported in the source paper (qualitative guarantee only). "
        "CrossState values come from experiment outputs."
    )
    return "\n".join(lines)


def sota_csv(crossstate: CrossStateResult) -> str:
    """Emit CSV for the SOTA comparison table."""
    header = (
        "system,year,platform,mechanism,guarantee,downtime_ms,state_transfer_records,"
        "migration_throughput_rps,packet_loss_percent,decision_agreement_percent,"
        "state_equivalence_percent,rollback_success_percent,per_record_ms,"
        "concurrent_traffic,cross_platform,verification_level"
    )
    rows = [header]

    cs = crossstate
    cs_row = (
        f"CrossState,2026,BMv2 (P4) <-> XDP (eBPF),schema-level quiesced checkpoint,"
        f"exact equivalence + audit,{cs.downtime_ms},{cs.records_written},"
        f"{cs.records_written / cs.total_checkpoint_seconds if cs.total_checkpoint_seconds else ''},"
        f"{cs.packet_loss_percent},{cs.decision_agreement_percent},"
        f"{cs.state_equivalence_percent},{cs.rollback_success_percent},"
        f"{cs.per_record_seconds},{cs.concurrent_traffic},{cs.cross_platform},{cs.verification_level}"
    )
    rows.append(cs_row)

    for ref in SOTA_REFERENCES.values():
        rows.append(
            f"{ref.name},{ref.year},{ref.platform},{ref.mechanism},{ref.guarantee},"
            f"{ref.downtime_ms},{ref.state_transfer_records},{ref.migration_throughput_rps},"
            f"{ref.packet_loss_percent},{ref.decision_agreement_percent},"
            f"{ref.state_equivalence_percent},{ref.rollback_success_percent},"
            f"{ref.per_record_ms},{ref.concurrent_traffic},{ref.cross_platform},"
            f"{ref.verification_level}"
        )
    return "\n".join(rows) + "\n"


def sota_json(crossstate: CrossStateResult) -> dict[str, Any]:
    """Emit JSON for the SOTA comparison table."""
    cs = crossstate
    payload = {
        "crossstate": {
            "experiment": cs.experiment,
            "checkpoints": cs.checkpoints,
            "total_checkpoint_seconds": cs.total_checkpoint_seconds,
            "per_record_seconds": cs.per_record_seconds,
            "records_written": cs.records_written,
            "records_total": cs.records_total,
            "delta_reduction_percent": cs.delta_reduction_percent,
            "packet_loss_percent": cs.packet_loss_percent,
            "decision_agreement_percent": cs.decision_agreement_percent,
            "state_equivalence_percent": cs.state_equivalence_percent,
            "rollback_success_percent": cs.rollback_success_percent,
            "source_stability_pass": cs.source_stability_pass,
            "flows_disrupted": cs.flows_disrupted,
            "flows_total": cs.flows_total,
            "downtime_ms": cs.downtime_ms,
            "concurrent_traffic": cs.concurrent_traffic,
            "cross_platform": cs.cross_platform,
            "verification_level": cs.verification_level,
        },
        "sota_references": {k: asdict(v) for k, v in SOTA_REFERENCES.items()},
    }
    return payload
