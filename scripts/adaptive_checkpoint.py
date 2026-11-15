#!/usr/bin/env python3
"""
CrossState Adaptive Checkpoint Scheduler.

Implements ML-based adaptive checkpoint scheduling that predicts optimal
checkpoint timing based on traffic patterns. Uses a simple moving average
and variance-based approach to detect low-traffic windows for checkpoint
execution, reducing migration overhead.

The scheduler tracks packet arrival rates over sliding windows and
identifies periods of low traffic intensity as optimal checkpoint windows.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TrafficSample:
    """A single traffic measurement sample."""
    timestamp: float
    packet_count: int
    byte_count: int
    flow_count: int


@dataclass
class CheckpointWindow:
    """A recommended checkpoint window."""
    start_time: float
    end_time: float
    confidence: float  # 0.0 to 1.0
    expected_duration_ms: float
    reason: str


class AdaptiveCheckpointScheduler:
    """
    Adaptive checkpoint scheduler that predicts optimal checkpoint timing
    based on traffic patterns.

    Uses a sliding window of traffic samples to compute:
    - Moving average packet rate
    - Variance in packet rate (burstiness)
    - Low-traffic window detection

    The scheduler recommends checkpoint windows when:
    1. Traffic rate is below a threshold (low activity)
    2. Traffic variance is low (predictable, not bursty)
    3. Sufficient time has elapsed since last checkpoint
    """

    def __init__(
        self,
        window_size: int = 60,  # seconds
        sample_interval: float = 1.0,  # seconds
        low_traffic_threshold: float = 100.0,  # packets/sec
        max_burstiness: float = 0.5,  # coefficient of variation threshold
        min_checkpoint_interval_ms: float = 1000.0,  # min time between checkpoints
    ):
        self.window_size = window_size
        self.sample_interval = sample_interval
        self.low_traffic_threshold = low_traffic_threshold
        self.max_burstiness = max_burstiness
        self.min_checkpoint_interval_ms = min_checkpoint_interval_ms

        self._samples: deque[TrafficSample] = deque(maxlen=window_size)
        self._last_checkpoint_time: float | None = None
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._checkpoint_count: int = 0

    def record_traffic(self, packet_count: int, byte_count: int = 0,
                       flow_count: int = 0,
                       timestamp: float | None = None) -> None:
        """Record a traffic measurement sample."""
        if timestamp is None:
            timestamp = time.time()
        self._samples.append(TrafficSample(
            timestamp=timestamp,
            packet_count=packet_count,
            byte_count=byte_count,
            flow_count=flow_count,
        ))
        self._total_packets += packet_count
        self._total_bytes += byte_count

    def _compute_stats(self) -> dict[str, float]:
        """Compute traffic statistics from samples."""
        if not self._samples:
            return {
                "avg_rate": 0.0,
                "std_rate": 0.0,
                "cv": 0.0,  # coefficient of variation
                "min_rate": 0.0,
                "max_rate": 0.0,
                "sample_count": 0,
            }

        rates = [s.packet_count / self.sample_interval for s in self._samples]
        n = len(rates)
        avg = sum(rates) / n
        variance = sum((r - avg) ** 2 for r in rates) / n
        std = math.sqrt(variance)
        cv = std / avg if avg > 0 else 0.0

        return {
            "avg_rate": avg,
            "std_rate": std,
            "cv": cv,
            "min_rate": min(rates),
            "max_rate": max(rates),
            "sample_count": n,
        }

    def should_checkpoint(self, current_time: float | None = None) -> CheckpointWindow | None:
        """
        Determine if a checkpoint should be triggered now.

        Returns a CheckpointWindow if conditions are favorable, None otherwise.
        """
        if current_time is None:
            current_time = time.time()

        # Check minimum checkpoint interval
        if self._last_checkpoint_time is not None:
            elapsed_ms = (current_time - self._last_checkpoint_time) * 1000
            if elapsed_ms < self.min_checkpoint_interval_ms:
                return None

        stats = self._compute_stats()

        # Need enough samples for meaningful statistics
        if stats["sample_count"] < 5:
            return None

        # Check low traffic condition
        if stats["avg_rate"] > self.low_traffic_threshold:
            return None

        # Check burstiness (coefficient of variation)
        if stats["cv"] > self.max_burstiness:
            return None

        # Compute confidence based on how low traffic is and how stable
        traffic_score = max(0.0, 1.0 - stats["avg_rate"] / self.low_traffic_threshold)
        stability_score = max(0.0, 1.0 - stats["cv"] / self.max_burstiness)
        confidence = (traffic_score + stability_score) / 2.0

        # Estimate checkpoint duration based on historical data
        expected_duration_ms = 100.0  # Default estimate

        return CheckpointWindow(
            start_time=current_time,
            end_time=current_time + expected_duration_ms / 1000.0,
            confidence=confidence,
            expected_duration_ms=expected_duration_ms,
            reason=(
                f"Low traffic ({stats['avg_rate']:.1f} pkt/s), "
                f"stable (CV={stats['cv']:.2f})"
            ),
        )

    def record_checkpoint(self, timestamp: float | None = None) -> None:
        """Record that a checkpoint was executed."""
        if timestamp is None:
            timestamp = time.time()
        self._last_checkpoint_time = timestamp
        self._checkpoint_count += 1

    def get_stats(self) -> dict[str, Any]:
        """Return scheduler statistics."""
        stats = self._compute_stats()
        stats.update({
            "total_packets": self._total_packets,
            "total_bytes": self._total_bytes,
            "checkpoint_count": self._checkpoint_count,
            "low_traffic_threshold": self.low_traffic_threshold,
            "max_burstiness": self.max_burstiness,
            "last_checkpoint_time": self._last_checkpoint_time,
        })
        return stats


class AdaptiveCheckpointManager:
    """
    High-level manager that integrates adaptive checkpoint scheduling
    with the CrossState migration protocol.

    Coordinates between the scheduler and the migration protocol to
    automatically trigger checkpoints during optimal windows.
    """

    def __init__(
        self,
        source_target: Any,
        dest_target: Any,
        scheduler: AdaptiveCheckpointScheduler | None = None,
    ):
        self.source = source_target
        self.dest = dest_target
        self.scheduler = scheduler or AdaptiveCheckpointScheduler()
        self._checkpoint_history: list[dict] = []

    def record_traffic(self, packet_count: int, byte_count: int = 0,
                       flow_count: int = 0) -> None:
        """Record traffic measurement."""
        self.scheduler.record_traffic(packet_count, byte_count, flow_count)

    def should_checkpoint_now(self) -> CheckpointWindow | None:
        """Check if a checkpoint should be triggered now."""
        return self.scheduler.should_checkpoint()

    def execute_checkpoint(self, records: list[Any]) -> dict:
        """Execute a checkpoint using atomic migration."""
        from scripts.live_migration import atomic_migrate

        start_time = time.time()
        success = atomic_migrate(self.source, self.dest, records)
        end_time = time.time()

        self.scheduler.record_checkpoint(start_time)

        result = {
            "timestamp": start_time,
            "success": success,
            "duration_ms": (end_time - start_time) * 1000,
            "record_count": len(records),
        }
        self._checkpoint_history.append(result)
        return result

    def get_stats(self) -> dict[str, Any]:
        """Return combined scheduler and checkpoint statistics."""
        scheduler_stats = self.scheduler.get_stats()
        scheduler_stats["checkpoint_history_count"] = len(self._checkpoint_history)
        if self._checkpoint_history:
            durations = [c["duration_ms"] for c in self._checkpoint_history]
            scheduler_stats["avg_checkpoint_duration_ms"] = sum(durations) / len(durations)
            scheduler_stats["max_checkpoint_duration_ms"] = max(durations)
            scheduler_stats["min_checkpoint_duration_ms"] = min(durations)
        return scheduler_stats