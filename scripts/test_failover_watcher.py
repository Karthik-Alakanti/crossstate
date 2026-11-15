#!/usr/bin/env python3
"""
CrossState Failover Watcher Validation Test

Tests the automatic failover watcher against simulated datapath failures:
1. Primary becomes unreachable -> failover to standby triggered
2. Standby is healthy -> failover succeeds
3. Primary recovers -> failback triggered
4. Both primary and standby unreachable -> no failover possible

Uses mock DatapathTarget objects (no real hardware required).

Run: python3 scripts/test_failover_watcher.py
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.datapath_hal import (
    DatapathTarget, DatapathHealth, DatapathRecord,
)
from scripts.automatic_failover import FailoverWatcher, FailoverState, FailoverEvent

RESULTS = {
    "failover_on_primary_failure": None,
    "failback_on_primary_recovery": None,
    "no_failover_when_both_unreachable": None,
    "health_degraded_detection": None,
}


class MockTarget(DatapathTarget):
    """Mock datapath target that can simulate health states."""

    def __init__(self, name: str, target_type: str,
                 healthy: bool = True,
                 fail_after_n_checks: Optional[int] = None,
                 recover_after_n_checks: Optional[int] = None,
                 hardware: bool = False):
        super().__init__(name, target_type)
        self._healthy = healthy
        self._fail_after_n = fail_after_n_checks
        self._recover_after_n = recover_after_n_checks
        self._check_count = 0
        self._hardware = hardware
        self._write_count = 0
        self._records: dict[int, DatapathRecord] = {}

    def health_check(self) -> DatapathHealth:
        self._check_count += 1

        # Handle failure after N checks (checked first)
        if self._fail_after_n is not None and self._check_count >= self._fail_after_n:
            self._healthy = False

        # Handle recovery after N checks (takes precedence over failure)
        if self._recover_after_n is not None and self._check_count >= self._recover_after_n:
            self._healthy = True

        t0 = datetime.now(timezone.utc)
        if self._healthy:
            self.consecutive_failures = 0
            return DatapathHealth(
                target=self.name, reachable=True,
                last_check_utc=t0.isoformat(),
                latency_ms=1.0, consecutive_failures=0,
            )
        else:
            self.consecutive_failures += 1
            return DatapathHealth(
                target=self.name, reachable=False,
                last_check_utc=t0.isoformat(),
                error="simulated failure",
                consecutive_failures=self.consecutive_failures,
            )

    def export_all(self) -> list[DatapathRecord]:
        return list(self._records.values())

    def read_slot(self, slot: int) -> DatapathRecord | None:
        return self._records.get(slot)

    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        self._write_count += 1
        self._records[record.slot] = record

    def clear_slot(self, slot: int) -> None:
        self._records.pop(slot, None)

    def is_hardware(self) -> bool:
        return self._hardware

    def is_available(self) -> bool:
        return self._healthy


def test_failover_on_primary_failure() -> dict:
    """Test 1: Primary becomes unreachable -> failover to standby triggered."""
    print("Test 1: Failover on primary failure")

    primary = MockTarget("primary-bmv2", "P4/BMv2 (software)",
                         healthy=True, fail_after_n_checks=2)
    standby = MockTarget("standby-xdp", "eBPF/XDP (software)",
                         healthy=True)

    watcher = FailoverWatcher(primary, standby,
                              interval_sec=0.01,
                              max_failures=2,
                              stop_copy_ms=10.0)

    # Run watcher for a few iterations
    watcher.run(max_iterations=10)

    # Check that failover was triggered
    failover_events = [e for e in watcher.state.events
                       if e.event_type == "failover"]
    success = len(failover_events) > 0

    # After failover, roles should be swapped
    roles_swapped = (watcher.state.primary == "standby-xdp" and
                     watcher.state.standby == "primary-bmv2")

    print(f"  Failover events: {len(failover_events)}")
    print(f"  Roles swapped: {roles_swapped}")
    print(f"  New primary: {watcher.state.primary}")
    print(f"  New standby: {watcher.state.standby}")

    return {
        "status": "PASS" if (success and roles_swapped) else "FAIL",
        "failover_events": len(failover_events),
        "roles_swapped": roles_swapped,
        "breakpoint": "Failover triggered on primary failure",
    }


def test_failback_on_primary_recovery() -> dict:
    """Test 2: Primary recovers -> failback triggered."""
    print("Test 2: Failback on primary recovery")

    primary = MockTarget("primary-bmv2", "P4/BMv2 (software)",
                         healthy=True, fail_after_n_checks=2,
                         recover_after_n_checks=5)
    standby = MockTarget("standby-xdp", "eBPF/XDP (software)",
                         healthy=True)

    watcher = FailoverWatcher(primary, standby,
                              interval_sec=0.01,
                              max_failures=2,
                              stop_copy_ms=10.0)

    watcher.run(max_iterations=15)

    # Check that failover was triggered first
    failover_events = [e for e in watcher.state.events
                       if e.event_type == "failover"]
    # Check that failback was triggered after recovery
    failback_events = [e for e in watcher.state.events
                       if e.event_type == "failback"]

    # After failback, roles should be swapped back
    roles_restored = (watcher.state.primary == "primary-bmv2" and
                      watcher.state.standby == "standby-xdp")

    print(f"  Failover events: {len(failover_events)}")
    print(f"  Failback events: {len(failback_events)}")
    print(f"  Roles restored: {roles_restored}")
    print(f"  Primary: {watcher.state.primary}")
    print(f"  Standby: {watcher.state.standby}")

    return {
        "status": "PASS" if (len(failover_events) > 0 and
                            len(failback_events) > 0 and roles_restored) else "FAIL",
        "failover_events": len(failover_events),
        "failback_events": len(failback_events),
        "roles_restored": roles_restored,
        "breakpoint": "Failback triggered on primary recovery",
    }


def test_no_failover_when_both_unreachable() -> dict:
    """Test 3: Both primary and standby unreachable -> no failover possible."""
    print("Test 3: No failover when both unreachable")

    primary = MockTarget("primary-bmv2", "P4/BMv2 (software)",
                         healthy=True, fail_after_n_checks=1)
    standby = MockTarget("standby-xdp", "eBPF/XDP (software)",
                         healthy=True, fail_after_n_checks=1)

    watcher = FailoverWatcher(primary, standby,
                              interval_sec=0.01,
                              max_failures=1,
                              stop_copy_ms=10.0)

    watcher.run(max_iterations=5)

    # Check that no failover was triggered (both unreachable)
    failover_events = [e for e in watcher.state.events
                       if e.event_type == "failover"]
    both_unreachable_logged = any(
        "Both primary and standby unreachable" in e.reason
        for e in watcher.state.events
    )

    print(f"  Failover events: {len(failover_events)} (expected: 0)")
    print(f"  Both unreachable logged: {both_unreachable_logged}")

    return {
        "status": "PASS" if (len(failover_events) == 0 and
                            both_unreachable_logged) else "FAIL",
        "failover_events": len(failover_events),
        "both_unreachable_logged": both_unreachable_logged,
        "breakpoint": "No failover when both targets unreachable",
    }


def test_health_degraded_detection() -> dict:
    """Test 4: Primary degraded but still reachable -> health_degraded event."""
    print("Test 4: Health degraded detection")

    primary = MockTarget("primary-bmv2", "P4/BMv2 (software)",
                         healthy=True, fail_after_n_checks=3)
    standby = MockTarget("standby-xdp", "eBPF/XDP (software)",
                         healthy=True)

    watcher = FailoverWatcher(primary, standby,
                              interval_sec=0.01,
                              max_failures=3,
                              stop_copy_ms=10.0)

    watcher.run(max_iterations=4)

    # Check that health_degraded event was logged
    degraded_events = [e for e in watcher.state.events
                       if e.event_type == "health_degraded"]

    print(f"  Health degraded events: {len(degraded_events)}")

    return {
        "status": "PASS" if len(degraded_events) > 0 else "FAIL",
        "degraded_events": len(degraded_events),
        "breakpoint": "Health degraded detected before failover threshold",
    }


def main():
    print("=" * 60)
    print("CrossState Failover Watcher Validation Test")
    print("Testing automatic failover with simulated datapath failures")
    print("=" * 60)
    print()

    results = {}

    results["failover_on_primary_failure"] = test_failover_on_primary_failure()
    print()

    results["failback_on_primary_recovery"] = test_failback_on_primary_recovery()
    print()

    results["no_failover_when_both_unreachable"] = test_no_failover_when_both_unreachable()
    print()

    results["health_degraded_detection"] = test_health_degraded_detection()
    print()

    # Summary
    print("=" * 60)
    print("FAILOVER WATCHER TEST SUMMARY")
    print("=" * 60)

    all_pass = True
    for name, result in results.items():
        status = result.get("status", "UNKNOWN")
        breakpoint = result.get("breakpoint", "N/A")
        passed = status == "PASS"
        all_pass = all_pass and passed
        print(f"  {name}: {status} | {breakpoint}")

    print()
    if all_pass:
        print("OVERALL: All failover watcher tests passed.")
    else:
        print("OVERALL: Some failover watcher tests FAILED.")

    # Write results to file
    output = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "overall_pass": all_pass,
        "results": results,
    }
    output_path = ROOT / "artifacts" / "failover_watcher_test_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        __import__("json").dumps(output, indent=2) + "\n"
    )
    print(f"\nResults written to {output_path}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
