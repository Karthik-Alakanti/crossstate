#!/usr/bin/env python3
"""
CrossState Flow-Aware Adaptive Cutover.

Detects idle windows in traffic flow patterns for optimal cutover timing.
Instead of a fixed stop-and-copy window, the cutover is scheduled during
naturally occurring traffic lulls, minimizing disruption to active flows.

Uses per-flow inter-arrival time tracking to detect when flows are idle,
then schedules cutover during the largest contiguous idle window.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class FlowActivity:
    """Tracks activity for a single flow."""
    flow_key: tuple
    last_packet_time: float
    packet_count: int
    byte_count: int
    inter_arrival_times: deque = field(default_factory=lambda: deque(maxlen=10))


@dataclass
class IdleWindow:
    """Represents a detected idle window for cutover."""
    start_time: float
    end_time: float
    duration_ms: float
    active_flow_count: int
    confidence: float  # 0.0 to 1.0


class FlowActivityTracker:
    """Tracks per-flow activity to detect idle windows."""

    def __init__(self, idle_timeout_ms: float = 500.0):
        self.idle_timeout_ms = idle_timeout_ms
        self._flows: dict[tuple, FlowActivity] = {}
        self._global_last_packet_time: float | None = None

    def record_packet(self, flow_key: tuple, timestamp: float | None = None,
                      byte_count: int = 0) -> None:
        """Record a packet for a flow."""
        if timestamp is None:
            timestamp = time.time()

        if flow_key not in self._flows:
            self._flows[flow_key] = FlowActivity(
                flow_key=flow_key,
                last_packet_time=timestamp,
                packet_count=0,
                byte_count=0,
            )

        flow = self._flows[flow_key]
        if flow.packet_count > 0:
            inter_arrival = timestamp - flow.last_packet_time
            flow.inter_arrival_times.append(inter_arrival)

        flow.last_packet_time = timestamp
        flow.packet_count += 1
        flow.byte_count += byte_count
        self._global_last_packet_time = timestamp

    def get_idle_windows(self, current_time: float | None = None,
                         min_idle_ms: float = 100.0) -> list[IdleWindow]:
        """
        Detect idle windows where no flow has been active.

        Returns a list of IdleWindow objects sorted by duration (largest first).
        """
        if current_time is None:
            current_time = time.time()

        idle_windows = []
        active_flows = 0

        for flow_key, flow in self._flows.items():
            idle_time_ms = (current_time - flow.last_packet_time) * 1000
            if idle_time_ms < self.idle_timeout_ms:
                active_flows += 1
                continue

            # Flow is idle
            idle_windows.append(IdleWindow(
                start_time=flow.last_packet_time,
                end_time=current_time,
                duration_ms=idle_time_ms,
                active_flow_count=active_flows,
                confidence=min(1.0, idle_time_ms / self.idle_timeout_ms),
            ))

        # Sort by duration (largest first)
        idle_windows.sort(key=lambda w: w.duration_ms, reverse=True)

        # Filter to windows meeting minimum idle duration
        idle_windows = [w for w in idle_windows if w.duration_ms >= min_idle_ms]

        return idle_windows

    def get_best_cutover_window(self, current_time: float | None = None,
                                min_duration_ms: float = 100.0) -> IdleWindow | None:
        """Get the best idle window for cutover."""
        windows = self.get_idle_windows(current_time, min_duration_ms)
        if not windows:
            return None
        return windows[0]

    def get_active_flow_count(self, current_time: float | None = None,
                              idle_timeout_ms: float | None = None) -> int:
        """Count flows that have been active recently."""
        if current_time is None:
            current_time = time.time()
        if idle_timeout_ms is None:
            idle_timeout_ms = self.idle_timeout_ms

        count = 0
        for flow in self._flows.values():
            idle_time_ms = (current_time - flow.last_packet_time) * 1000
            if idle_time_ms < idle_timeout_ms:
                count += 1
        return count

    def get_stats(self) -> dict:
        """Return flow activity statistics."""
        current_time = time.time()
        active = self.get_active_flow_count(current_time)
        total = len(self._flows)
        idle = total - active

        return {
            "total_flows": total,
            "active_flows": active,
            "idle_flows": idle,
            "idle_timeout_ms": self.idle_timeout_ms,
            "global_last_packet_time": self._global_last_packet_time,
        }


class AdaptiveCutoverManager:
    """
    Manages flow-aware adaptive cutover for CrossState migration.

    Instead of a fixed stop-and-copy window, the cutover is scheduled during
    naturally occurring traffic lulls, minimizing disruption to active flows.
    """

    def __init__(self, source_target: Any, dest_target: Any,
                 idle_timeout_ms: float = 500.0,
                 min_cutover_window_ms: float = 100.0,
                 max_wait_ms: float = 5000.0):
        self.source = source_target
        self.dest = dest_target
        self.tracker = FlowActivityTracker(idle_timeout_ms=idle_timeout_ms)
        self.min_cutover_window_ms = min_cutover_window_ms
        self.max_wait_ms = max_wait_ms
        self._cutover_history: list[dict] = []

    def record_packet(self, flow_key: tuple, timestamp: float | None = None,
                      byte_count: int = 0) -> None:
        """Record a packet for flow activity tracking."""
        self.tracker.record_packet(flow_key, timestamp, byte_count)

    def find_cutover_window(self, current_time: float | None = None) -> IdleWindow | None:
        """Find the best cutover window based on current traffic patterns."""
        return self.tracker.get_best_cutover_window(
            current_time, self.min_cutover_window_ms
        )

    def wait_for_cutover_window(self, max_wait_ms: float | None = None,
                                check_interval_ms: float = 50.0) -> IdleWindow | None:
        """
        Wait for a suitable cutover window.

        Polls flow activity until an idle window of sufficient duration is found
        or the maximum wait time is exceeded.
        """
        if max_wait_ms is None:
            max_wait_ms = self.max_wait_ms

        start_time = time.time()
        while True:
            current_time = time.time()
            elapsed_ms = (current_time - start_time) * 1000

            if elapsed_ms >= max_wait_ms:
                # Return best available window even if small
                window = self.tracker.get_best_cutover_window(
                    current_time, self.min_cutover_window_ms
                )
                return window

            window = self.find_cutover_window(current_time)
            if window is not None:
                return window

            time.sleep(check_interval_ms / 1000.0)

        return None

    def execute_cutover(self, records: list[Any],
                        window: IdleWindow | None = None) -> dict:
        """Execute cutover during the best available window."""
        if window is None:
            window = self.find_cutover_window()

        start_time = time.time()

        # Mark all records as synced (ready for traffic)
        for rec in records:
            rec.synced = 1

        # Write to destination
        for rec in records:
            self.dest.write_record(rec, verify=False)

        end_time = time.time()

        result = {
            "timestamp": start_time,
            "success": True,
            "duration_ms": (end_time - start_time) * 1000,
            "record_count": len(records),
            "cutover_window": {
                "start_time": window.start_time if window else None,
                "end_time": window.end_time if window else None,
                "duration_ms": window.duration_ms if window else None,
                "confidence": window.confidence if window else None,
            } if window else None,
            "active_flow_count": self.tracker.get_active_flow_count(),
        }
        self._cutover_history.append(result)
        return result

    def get_stats(self) -> dict[str, Any]:
        """Return cutover manager statistics."""
        flow_stats = self.tracker.get_stats()
        if self._cutover_history:
            durations = [c["duration_ms"] for c in self._cutover_history]
            flow_stats["avg_cutover_duration_ms"] = sum(durations) / len(durations)
            flow_stats["cutover_count"] = len(self._cutover_history)
        return flow_stats