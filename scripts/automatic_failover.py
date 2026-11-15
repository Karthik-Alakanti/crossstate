#!/usr/bin/env python3
"""CrossState automatic failover watcher.

Monitors the health of the primary (source) datapath target. When the primary
becomes unreachable (consecutive health-check failures >= threshold), the
watcher automatically triggers a live migration (pre-copy + stop-and-copy +
cutover) to the standby (destination) target, achieving automatic failover
without operator intervention.

After failover, the roles are swapped: the old destination becomes the new
primary. A separate --failback flag can restore the original primary once it
recovers.

Health checking:
  - Each target is probed every --interval seconds
  - Failure threshold: --max-failures consecutive failed probes
  - On failure: trigger live migration to standby
  - Failover decision is recorded in a JSON event log

Works with any DatapathTarget backend via scripts/datapath_hal.py.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.datapath_hal import (
    DatapathTarget, DatapathHealth, create_target,
)
from scripts.live_migration import LiveMigrator, LiveMigrationResult

DEFAULT_INTERVAL_SEC = 2.0
DEFAULT_MAX_FAILURES = 3


def log(message: str) -> None:
    print(message, flush=True)


@dataclass
class FailoverEvent:
    """A single failover/failback event."""
    event_type: str  # "failover" | "failback" | "health_degraded" | "health_recovered"
    timestamp_utc: str
    primary_target: str
    standby_target: str
    reason: str
    migration_result: dict[str, Any] | None = None


@dataclass
class FailoverState:
    """Current failover watcher state."""
    primary: str
    standby: str
    primary_failed: bool = False
    failover_count: int = 0
    last_event: FailoverEvent | None = None
    events: list[FailoverEvent] = field(default_factory=list)


class FailoverWatcher:
    """Monitors datapath health and triggers automatic failover."""

    def __init__(self, primary: DatapathTarget, standby: DatapathTarget,
                 interval_sec: float = DEFAULT_INTERVAL_SEC,
                 max_failures: int = DEFAULT_MAX_FAILURES,
                 stop_copy_ms: float = 100.0,
                 event_log: Path | None = None):
        self.primary = primary
        self.standby = standby
        self.interval_sec = interval_sec
        self.max_failures = max_failures
        self.stop_copy_ms = stop_copy_ms
        self.event_log = event_log
        self.state = FailoverState(primary=primary.name, standby=standby.name)
        self._running = False
        self._stop_requested = False

    def _record_event(self, event_type: str, reason: str,
                      migration_result: LiveMigrationResult | None = None) -> None:
        event = FailoverEvent(
            event_type=event_type,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            primary_target=self.state.primary,
            standby_target=self.state.standby,
            reason=reason,
            migration_result=migration_result.to_dict(migration_result)
            if migration_result else None,
        )
        self.state.last_event = event
        self.state.events.append(event)
        log(f"[FAILOVER EVENT] {event_type} at {event.timestamp_utc}: {reason}")
        if self.event_log:
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            existing = []
            if self.event_log.exists():
                try:
                    existing = json.loads(self.event_log.read_text())
                except Exception:
                    existing = []
            existing.append(asdict(event))
            self.event_log.write_text(json.dumps(existing, indent=2) + "\n")

    def _check_health(self, target: DatapathTarget) -> DatapathHealth:
        return target.health_check()

    def _trigger_failover(self) -> LiveMigrationResult | None:
        """Migrate state from primary to standby and swap roles."""
        log(f"Triggering automatic failover: {self.state.primary} -> {self.state.standby}")
        migrator = LiveMigrator(
            self.primary, self.standby,
            stop_copy_ms=self.stop_copy_ms,
        )
        try:
            result = migrator.run()
        except Exception as exc:
            log(f"Automatic failover migration FAILED: {exc}")
            self._record_event("failover", f"Migration failed: {exc}")
            return None

        # Swap roles: standby becomes primary
        self.primary, self.standby = self.standby, self.primary
        self.state.primary = self.primary.name
        self.state.standby = self.standby.name
        self.state.primary_failed = False
        self.state.failover_count += 1

        self._record_event("failover",
                           f"Automatic failover complete: {result.status}",
                           migration_result=result)
        log(f"Failover #{self.state.failover_count} complete. "
            f"New primary: {self.state.primary}, new standby: {self.state.standby}")
        return result

    def _trigger_failback(self) -> LiveMigrationResult | None:
        """Migrate state back to the original primary once it recovers."""
        log(f"Triggering automatic failback: {self.state.standby} -> {self.state.primary}")
        migrator = LiveMigrator(
            self.standby, self.primary,
            stop_copy_ms=self.stop_copy_ms,
        )
        try:
            result = migrator.run()
        except Exception as exc:
            log(f"Automatic failback migration FAILED: {exc}")
            self._record_event("failback", f"Migration failed: {exc}")
            return None

        self.primary, self.standby = self.standby, self.primary
        self.state.primary = self.primary.name
        self.state.standby = self.standby.name
        self.state.primary_failed = False

        self._record_event("failback",
                           f"Automatic failback complete: {result.status}",
                           migration_result=result)
        log(f"Failback complete. New primary: {self.state.primary}")
        return result

    def run_once(self) -> bool:
        """Single health-check iteration. Returns True if a failover/failback occurred."""
        primary_health = self._check_health(self.primary)
        standby_health = self._check_health(self.standby)

        # Log health status periodically
        log(f"Health: primary={self.state.primary} "
            f"reachable={primary_health.reachable} "
            f"failures={primary_health.consecutive_failures} | "
            f"standby={self.state.standby} "
            f"reachable={standby_health.reachable} "
            f"failures={standby_health.consecutive_failures}")

        # Primary degraded but still reachable
        if (primary_health.reachable and
                primary_health.consecutive_failures > 0 and
                primary_health.consecutive_failures < self.max_failures):
            self._record_event("health_degraded",
                               f"Primary {self.state.primary} has "
                               f"{primary_health.consecutive_failures} "
                               f"consecutive failures but still reachable")

        # Primary failed: trigger failover if standby is healthy
        if (not primary_health.reachable and
                primary_health.consecutive_failures >= self.max_failures and
                not self.state.primary_failed):
            if standby_health.reachable:
                self.state.primary_failed = True
                self._trigger_failover()
                return True
            else:
                log(f"CRITICAL: Primary {self.state.primary} failed AND "
                    f"standby {self.state.standby} is unreachable. "
                    f"No failover possible.")
                self._record_event("health_degraded",
                                   "Both primary and standby unreachable")

        # Primary recovered: trigger failback if enabled
        if (primary_health.reachable and self.state.primary_failed):
            self._trigger_failback()
            return True

        return False

    def run(self, max_iterations: int | None = None) -> None:
        """Run the watcher loop until stopped."""
        self._running = True
        iteration = 0
        log(f"=== CrossState Automatic Failover Watcher ===")
        log(f"Primary: {self.state.primary} ({self.primary.target_type})")
        log(f"Standby: {self.state.standby} ({self.standby.target_type})")
        log(f"Interval: {self.interval_sec}s, Max failures: {self.max_failures}")
        log("Press Ctrl+C to stop.")

        def handle_signal(signum, frame):
            self._stop_requested = True
            log("Stop requested; finishing current iteration...")

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        try:
            while self._running and not self._stop_requested:
                if max_iterations is not None and iteration >= max_iterations:
                    break
                self.run_once()
                iteration += 1
                if not self._stop_requested:
                    time.sleep(self.interval_sec)
        finally:
            self._running = False
            log(f"Watcher stopped. Failovers performed: {self.state.failover_count}")
            if self.event_log:
                log(f"Event log: {self.event_log}")

    def stop(self) -> None:
        self._stop_requested = True
        self._running = False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CrossState automatic failover watcher."
    )
    parser.add_argument("--primary", type=str, default="bmv2",
                        choices=["bmv2", "xdp", "tofino", "smartnic"],
                        help="Primary datapath target type.")
    parser.add_argument("--standby", type=str, default="xdp",
                        choices=["bmv2", "xdp", "tofino", "smartnic"],
                        help="Standby datapath target type.")
    parser.add_argument("--primary-thrift-port", type=int, default=9090)
    parser.add_argument("--standby-thrift-port", type=int, default=9091)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SEC,
                        help="Health check interval in seconds.")
    parser.add_argument("--max-failures", type=int, default=DEFAULT_MAX_FAILURES,
                        help="Consecutive failures before triggering failover.")
    parser.add_argument("--stop-copy-ms", type=float, default=100.0,
                        help="Stop-and-copy quiesce window during failover (ms).")
    parser.add_argument("--max-iterations", type=int, default=None,
                        help="Maximum watcher iterations (for testing).")
    parser.add_argument("--event-log", type=Path,
                        default=ROOT / "artifacts" / "failover_events.json",
                        help="Failover event log path.")
    args = parser.parse_args()

    try:
        primary = create_target(args.primary, thrift_port=args.primary_thrift_port)
        standby = create_target(args.standby, thrift_port=args.standby_thrift_port)
    except Exception as exc:
        print(f"Failed to create targets: {exc}", file=sys.stderr)
        return 2

    watcher = FailoverWatcher(
        primary, standby,
        interval_sec=args.interval,
        max_failures=args.max_failures,
        stop_copy_ms=args.stop_copy_ms,
        event_log=args.event_log,
    )

    try:
        watcher.run(max_iterations=args.max_iterations)
    except KeyboardInterrupt:
        watcher.stop()
        return 130

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
