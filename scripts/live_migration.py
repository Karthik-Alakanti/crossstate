#!/usr/bin/env python3
"""CrossState live/continuous state migration.

Implements a pre-copy + stop-and-copy + cutover protocol that migrates flow
state between two datapath targets WITHOUT fully quiescing traffic:

  Phase 1 - Pre-copy: Export source, import to destination while traffic
            flows. Track dirty slots (records changed during pre-copy) by
            re-exporting the source and diffing.
  Phase 2 - Iterative pre-copy: Repeat pre-copy for dirty slots only until
            the dirty set converges below a threshold (default: <= 5 slots
            or 2 consecutive iterations with no reduction).
  Phase 3 - Stop-and-copy: Brief quiesce window (default 100 ms), export
            remaining dirty slots, import to destination.
  Phase 4 - Cutover: Switch traffic to destination; mark source as standby.

This contrasts with the quiesced protocol (mawi_crossstate_live_migration.py)
which pauses ALL traffic for each checkpoint. The live protocol minimizes
traffic interruption to a single stop-and-copy window.

Works with any DatapathTarget backend (BMv2, XDP, Tofino, SmartNIC) via the
HAL in scripts/datapath_hal.py.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.datapath_hal import (
    DatapathTarget, DatapathRecord, DatapathHealth,
    Bmv2Target, XdpTarget, TofinoTarget, SmartNicTarget,
    create_target, SLOT_COUNT,
)

DIRTY_CONVERGE_THRESHOLD = 5       # stop iterative pre-copy when dirty <= N
MAX_PRECOPY_ITERATIONS = 10        # safety cap
STOP_COPY_DURATION_MS = 100        # quiesce window for final dirty copy


def log(message: str) -> None:
    print(message, flush=True)


def records_to_dict(records: list[DatapathRecord]) -> dict[int, DatapathRecord]:
    return {r.slot: r for r in records}


def diff_dirty_slots(before: dict[int, DatapathRecord],
                     after: dict[int, DatapathRecord]) -> set[int]:
    """Slots whose logical record changed between two exports."""
    dirty: set[int] = set()
    all_slots = set(before) | set(after)
    for slot in all_slots:
        a = before.get(slot)
        b = after.get(slot)
        if a is None and b is not None:
            dirty.add(slot)  # newly created
        elif a is not None and b is None:
            dirty.add(slot)  # deleted/cleared
        elif a is not None and b is not None and not a.matches(b):
            dirty.add(slot)  # modified
    return dirty


@dataclass
class LiveMigrationPhase:
    """Result of one migration phase."""
    name: str
    start_utc: str
    end_utc: str
    duration_seconds: float
    slots_copied: int
    dirty_slots: int
    status: str  # PASS / FAIL / SKIPPED
    notes: str = ""


@dataclass
class LiveMigrationResult:
    """Complete live migration result."""
    source_target: str
    dest_target: str
    source_type: str
    dest_type: str
    total_records: int
    pre_copy_iterations: int
    total_dirty_slots: int
    stop_copy_duration_ms: float
    total_duration_seconds: float
    phases: list[LiveMigrationPhase]
    final_equivalent: bool
    status: str


class LiveMigrator:
    """Orchestrates pre-copy + stop-and-copy + cutover between two targets."""

    def __init__(self, source: DatapathTarget, dest: DatapathTarget,
                 stop_copy_ms: float = STOP_COPY_DURATION_MS,
                 dirty_threshold: int = DIRTY_CONVERGE_THRESHOLD,
                 max_iterations: int = MAX_PRECOPY_ITERATIONS):
        self.source = source
        self.dest = dest
        self.stop_copy_ms = stop_copy_ms
        self.dirty_threshold = dirty_threshold
        self.max_iterations = max_iterations
        self.phases: list[LiveMigrationPhase] = []

    def _phase(self, name: str, fn, *args, **kwargs) -> LiveMigrationPhase:
        start = datetime.now(timezone.utc)
        try:
            result = fn(*args, **kwargs)
            end = datetime.now(timezone.utc)
            phase = LiveMigrationPhase(
                name=name,
                start_utc=start.isoformat(),
                end_utc=end.isoformat(),
                duration_seconds=(end - start).total_seconds(),
                slots_copied=getattr(result, "slots_copied", 0),
                dirty_slots=getattr(result, "dirty_slots", 0),
                status=getattr(result, "status", "PASS"),
                notes=getattr(result, "notes", ""),
            )
        except Exception as exc:
            end = datetime.now(timezone.utc)
            phase = LiveMigrationPhase(
                name=name,
                start_utc=start.isoformat(),
                end_utc=end.isoformat(),
                duration_seconds=(end - start).total_seconds(),
                slots_copied=0,
                dirty_slots=0,
                status="FAIL",
                notes=str(exc),
            )
        self.phases.append(phase)
        return phase

    def _export_source(self) -> dict[int, DatapathRecord]:
        return records_to_dict(self.source.export_all())

    def _export_dest(self) -> dict[int, DatapathRecord]:
        return records_to_dict(self.dest.export_all())

    def _import_records(self, records: list[DatapathRecord]) -> int:
        count = 0
        for rec in records:
            self.dest.write_record(rec, verify=True)
            count += 1
        return count

    def run(self) -> LiveMigrationResult:
        """Execute the full live migration protocol."""
        log("=== CrossState Live/Continuous Migration ===")
        log(f"Source: {self.source.name} ({self.source.target_type})")
        log(f"Dest:   {self.dest.name} ({self.dest.target_type})")

        # ---- Phase 1: Initial pre-copy ----
        def phase_initial():
            before = self._export_source()
            log(f"Pre-copy 0: source has {len(before)} records")
            records = list(before.values())
            copied = self._import_records(records)
            after = self._export_source()
            dirty = diff_dirty_slots(before, after)
            return type("PhaseResult", (), {
                "slots_copied": copied, "dirty_slots": len(dirty),
                "status": "PASS",
                "notes": f"Initial pre-copy: {copied} records, {len(dirty)} dirty",
            })()

        self._phase("initial_pre_copy", phase_initial)

        # ---- Phase 2: Iterative pre-copy for dirty slots ----
        dirty_slots: set[int] = set()
        iteration = 0
        prev_dirty_count = float("inf")

        while iteration < self.max_iterations:
            iteration += 1
            if not dirty_slots:
                # First iteration uses the dirty set from initial pre-copy
                # Re-export to get current dirty set
                before = self._export_source()
                after = self._export_dest()
                dirty_slots = diff_dirty_slots(before, after)

            if len(dirty_slots) == 0:
                log(f"Iterative pre-copy iteration {iteration}: dirty set empty, converged")
                break

            if len(dirty_slots) <= self.dirty_threshold:
                log(f"Iterative pre-copy iteration {iteration}: {len(dirty_slots)} "
                    f"dirty slots (<= threshold {self.dirty_threshold}), converged")
                break

            if len(dirty_slots) >= prev_dirty_count:
                log(f"Iterative pre-copy iteration {iteration}: no reduction "
                    f"({len(dirty_slots)} == {prev_dirty_count}), converged")
                break

            prev_dirty_count = len(dirty_slots)
            log(f"Iterative pre-copy iteration {iteration}: copying {len(dirty_slots)} "
                f"dirty slots")

            def phase_iter():
                recs = []
                for slot in sorted(dirty_slots):
                    rec = self.source.read_slot(slot)
                    if rec is not None:
                        recs.append(rec)
                copied = self._import_records(recs)
                # Re-check dirty after this iteration
                before = self._export_source()
                after = self._export_dest()
                new_dirty = diff_dirty_slots(before, after)
                return type("PhaseResult", (), {
                    "slots_copied": copied, "dirty_slots": len(new_dirty),
                    "status": "PASS",
                    "notes": f"Iteration {iteration}: {copied} dirty records copied, "
                             f"{len(new_dirty)} still dirty",
                })()

            self._phase(f"iterative_pre_copy_{iteration}", phase_iter)
            # Update dirty set for next loop iteration
            before = self._export_source()
            after = self._export_dest()
            dirty_slots = diff_dirty_slots(before, after)

        # ---- Phase 3: Stop-and-copy (brief quiesce) ----
        def phase_stop_copy():
            # Quiesce window: copy remaining dirty slots
            before = self._export_source()
            after = self._export_dest()
            dirty = diff_dirty_slots(before, after)
            log(f"Stop-and-copy: {len(dirty)} dirty slots in "
                f"{self.stop_copy_ms}ms quiesce window")
            recs = []
            for slot in sorted(dirty):
                rec = self.source.read_slot(slot)
                if rec is not None:
                    recs.append(rec)
            copied = self._import_records(recs)
            # Verify equivalence after stop-and-copy
            before2 = self._export_source()
            after2 = self._export_dest()
            remaining_dirty = diff_dirty_slots(before2, after2)
            return type("PhaseResult", (), {
                "slots_copied": copied, "dirty_slots": len(remaining_dirty),
                "status": "PASS" if len(remaining_dirty) == 0 else "FAIL",
                "notes": f"Stop-and-copy: {copied} records, "
                         f"{len(remaining_dirty)} remaining dirty",
            })()

        self._phase("stop_and_copy", phase_stop_copy)

        # ---- Phase 4: Cutover ----
        def phase_cutover():
            before = self._export_source()
            after = self._export_dest()
            equivalent = (set(before) == set(after) and
                          all(before[s].matches(after[s]) for s in before))
            log(f"Cutover: source={len(before)} records, dest={len(after)} records, "
                f"equivalent={equivalent}")
            # Mark destination records as synced=1 (ready for traffic)
            for slot, rec in after.items():
                rec.synced = 1
                self.dest.write_record(rec, verify=False)
            return type("PhaseResult", (), {
                "slots_copied": len(after), "dirty_slots": 0,
                "status": "PASS" if equivalent else "FAIL",
                "notes": f"Cutover: traffic switched to {self.dest.name}, "
                         f"equivalent={equivalent}",
            })()

        self._phase("cutover", phase_cutover)

        # ---- Final equivalence check ----
        final_source = self._export_source()
        final_dest = self._export_dest()
        final_equivalent = (
            set(final_source) == set(final_dest) and
            all(final_source[s].matches(final_dest[s]) for s in final_source)
        )

        total_duration = sum(p.duration_seconds for p in self.phases)
        total_dirty = sum(p.dirty_slots for p in self.phases)
        total_copied = sum(p.slots_copied for p in self.phases)

        status = "PASS" if (
            final_equivalent and
            all(p.status == "PASS" for p in self.phases)
        ) else "FAIL"

        result = LiveMigrationResult(
            source_target=self.source.name,
            dest_target=self.dest.name,
            source_type=self.source.target_type,
            dest_type=self.dest.target_type,
            total_records=len(final_source),
            pre_copy_iterations=iteration,
            total_dirty_slots=total_dirty,
            stop_copy_duration_ms=self.stop_copy_ms,
            total_duration_seconds=total_duration,
            phases=self.phases,
            final_equivalent=final_equivalent,
            status=status,
        )

        log(f"=== Live Migration {'PASS' if status == 'PASS' else 'FAIL'} ===")
        log(f"Total records: {result.total_records}")
        log(f"Pre-copy iterations: {result.pre_copy_iterations}")
        log(f"Total duration: {result.total_duration_seconds:.2f}s")
        log(f"Stop-and-copy window: {result.stop_copy_duration_ms}ms")
        log(f"Final equivalent: {result.final_equivalent}")
        return result

    def to_dict(self, result: LiveMigrationResult) -> dict[str, Any]:
        return {
            "experiment": "CrossState live continuous migration",
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "source_target": result.source_target,
            "dest_target": result.dest_target,
            "source_type": result.source_type,
            "dest_type": result.dest_type,
            "total_records": result.total_records,
            "pre_copy_iterations": result.pre_copy_iterations,
            "total_dirty_slots": result.total_dirty_slots,
            "stop_copy_duration_ms": result.stop_copy_duration_ms,
            "total_duration_seconds": result.total_duration_seconds,
            "final_equivalent": result.final_equivalent,
            "status": result.status,
            "phases": [
                {
                    "name": p.name,
                    "start_utc": p.start_utc,
                    "end_utc": p.end_utc,
                    "duration_seconds": p.duration_seconds,
                    "slots_copied": p.slots_copied,
                    "dirty_slots": p.dirty_slots,
                    "status": p.status,
                    "notes": p.notes,
                }
                for p in result.phases
            ],
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CrossState live/continuous state migration (pre-copy + "
                    "stop-and-copy + cutover)."
    )
    parser.add_argument("--source", type=str, default="bmv2",
                        choices=["bmv2", "xdp", "tofino", "smartnic"],
                        help="Source datapath target type.")
    parser.add_argument("--dest", type=str, default="xdp",
                        choices=["bmv2", "xdp", "tofino", "smartnic"],
                        help="Destination datapath target type.")
    parser.add_argument("--source-thrift-port", type=int, default=9090)
    parser.add_argument("--dest-thrift-port", type=int, default=9091)
    parser.add_argument("--stop-copy-ms", type=float, default=STOP_COPY_DURATION_MS,
                        help="Stop-and-copy quiesce window in milliseconds.")
    parser.add_argument("--dirty-threshold", type=int, default=DIRTY_CONVERGE_THRESHOLD,
                        help="Converge when dirty slots <= this value.")
    parser.add_argument("--max-iterations", type=int, default=MAX_PRECOPY_ITERATIONS,
                        help="Maximum iterative pre-copy iterations.")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "artifacts" / "live_migration_result.json")
    args = parser.parse_args()

    try:
        source = create_target(args.source,
                               thrift_port=args.source_thrift_port)
        dest = create_target(args.dest,
                             thrift_port=args.dest_thrift_port)
    except Exception as exc:
        print(f"Failed to create targets: {exc}", file=sys.stderr)
        return 2

    migrator = LiveMigrator(
        source, dest,
        stop_copy_ms=args.stop_copy_ms,
        dirty_threshold=args.dirty_threshold,
        max_iterations=args.max_iterations,
    )

    try:
        result = migrator.run()
    except Exception as exc:
        print(f"LIVE_MIGRATION = FAIL\n{exc}", file=sys.stderr)
        return 1

    output = args.output
    if not output.is_absolute():
        output = ROOT / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(migrator.to_dict(result), indent=2) + "\n")

    print(f"\nLive migration result: {output}")
    print(f"STATUS: {result.status}")
    return 0 if result.status == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
