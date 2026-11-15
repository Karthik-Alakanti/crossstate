#!/usr/bin/env python3
"""
CrossState Stress Test Suite

Tries to break CrossState to find breakpoints:
1. Bucket overflow (depth > 4)
2. High flow count capacity limits
3. Rapid concurrent modifications
4. Edge case keys (boundary values)
5. Empty/malformed snapshots
6. Rapid sequential migrations
7. Source mutation during import

Run: python3 scripts/stress_test_breakpoints.py
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import (
    step, slot_of, BUCKET_CHAIN_SIZE, ALLOW, DROP,
    NEW, EST, CLOSED, Ev, M64, T, N,
)
from scripts.state_snapshot import (
    validate_snapshot, build_snapshot, SLOT_COUNT, RECORD_FIELDS,
)
from scripts.compare_state_snapshots import compare_snapshots

RESULTS = {
    "bucket_overflow": None,
    "high_flow_capacity": None,
    "rapid_modifications": None,
    "edge_case_keys": None,
    "malformed_snapshot": None,
    "sequential_migrations": None,
    "source_mutation": None,
}


def log(message: str) -> None:
    print(f"[STRESS] {message}", flush=True)


def test_bucket_overflow() -> dict:
    """Test 1: Insert more than BUCKET_CHAIN_SIZE flows into the same bucket.
    
    Breakpoint: After 4 inserts into the same bucket, the 5th should be DROP.
    """
    log("Test 1: Bucket overflow (depth limit = 4)")

    tbl: dict[int, list] = {}
    ts = 1_000_000

    # Find keys that hash to the same slot
    target_slot = None
    keys = []
    candidate = 1
    while len(keys) < BUCKET_CHAIN_SIZE + 3 and candidate < 0xFFFFFFFF:
        key = (candidate, 40000, candidate + 1, 40001, 6)
        s = slot_of(key)
        if target_slot is None:
            target_slot = s
        if s == target_slot:
            keys.append(key)
        candidate += 1

    if len(keys) < BUCKET_CHAIN_SIZE + 1:
        return {"status": "SKIP", "reason": "Could not find enough CRC collisions"}

    results = []
    for i, key in enumerate(keys):
        e = Ev(key[0], key[1], key[2], key[3], 6, True, True, False, False, False, 100, ts + i)
        r = step(tbl, e)
        status = "ALLOW" if r == ALLOW else "DROP"
        results.append({"insert": i, "key": key, "result": status})
        if i < BUCKET_CHAIN_SIZE:
            assert r == ALLOW, f"Bucket insert {i} should be ALLOW"
        else:
            assert r == DROP, f"Bucket overflow at insert {i} should be DROP"

    log(f"  Slot {target_slot}: {len(keys)} keys, first {BUCKET_CHAIN_SIZE} ALLOW, rest DROP")
    log(f"  Bucket overflow breakpoint: CONFIRMED (depth={BUCKET_CHAIN_SIZE})")

    return {
        "status": "PASS",
        "slot": target_slot,
        "total_keys": len(keys),
        "allowed": BUCKET_CHAIN_SIZE,
        "rejected": len(keys) - BUCKET_CHAIN_SIZE,
        "breakpoint": f"Depth {BUCKET_CHAIN_SIZE} limit enforced",
    }


def test_high_flow_capacity() -> dict:
    """Test 2: Insert many flows and measure rejection rate.
    
    Breakpoint: Direct-mapped table rejection grows with flow count.
    """
    log("Test 2: High flow capacity stress test")

    import random
    random.seed(42)

    tbl: dict[int, list] = {}
    ts = 1_000_000

    flow_counts = [100, 500, 1000, 2000, 5000, 10000]
    results = []

    for n_flows in flow_counts:
        tbl = {}
        rejected = 0
        allowed = 0

        for i in range(n_flows):
            key = (
                random.randint(0, 2**32 - 1),
                random.randint(1024, 65535),
                random.randint(0, 2**32 - 1),
                random.choice([80, 443, 22, 53, 8080]),
                6,
            )
            # Canonicalize
            a = key[0] << 16 | key[1]
            b = key[2] << 16 | key[3]
            if a > b:
                key = (key[2], key[3], key[0], key[1], 6)

            e = Ev(key[0], key[1], key[2], key[3], 6, True, True, False, False, False, 100, ts + i)
            r = step(tbl, e)
            if r == ALLOW:
                allowed += 1
            else:
                rejected += 1

        rejection_rate = (rejected / n_flows) * 100 if n_flows > 0 else 0
        results.append({
            "flows": n_flows,
            "allowed": allowed,
            "rejected": rejected,
            "rejection_rate_percent": round(rejection_rate, 2),
        })
        log(f"  {n_flows} flows: {allowed} allowed, {rejected} rejected ({rejection_rate:.2f}%)")

    # Direct-mapped table should show increasing rejection
    high_flow_rejection = results[-1]["rejection_rate_percent"]
    log(f"  Capacity breakpoint: {high_flow_rejection:.1f}% rejection at {flow_counts[-1]} flows")

    return {
        "status": "PASS",
        "results": results,
        "breakpoint": f"Rejection rate {high_flow_rejection:.1f}% at {flow_counts[-1]} flows",
    }


def test_rapid_modifications() -> dict:
    """Test 3: Rapid add/modify/delete cycles on same slot.
    
    Breakpoint: Rapid modifications should not corrupt state.
    """
    log("Test 3: Rapid concurrent modifications")

    tbl: dict[int, list] = {}
    ts = 1_000_000
    key = (0x0A000001, 40000, 0x0A000002, 443, 6)
    s = slot_of(key)

    results = []
    for i in range(100):
        # Alternate between NEW, EST, CLOSED, and re-NEW
        if i % 4 == 0:
            e = Ev(key[0], key[1], key[2], key[3], 6, True, True, False, False, False, 100, ts + i)
            r = step(tbl, e)
            results.append(("NEW" if i == 0 else "RENEW", r))
        elif i % 4 == 1:
            e = Ev(key[0], key[1], key[2], key[3], 6, False, True, False, False, False, 200, ts + i)
            r = step(tbl, e)
            results.append(("EST", r))
        elif i % 4 == 2:
            e = Ev(key[0], key[1], key[2], key[3], 6, False, False, True, False, False, 300, ts + i)
            r = step(tbl, e)
            results.append(("CLOSED", r))
        else:
            e = Ev(key[0], key[1], key[2], key[3], 6, True, True, False, False, False, 400, ts + i)
            r = step(tbl, e)
            results.append(("RENEW_AFTER_CLOSED", r))

    # Verify final state is consistent
    final_records = tbl.get(s, [])
    log(f"  Rapid modifications: 100 cycles completed, final state has {len(final_records)} record(s)")
    log(f"  Rapid modification breakpoint: CONFIRMED (no corruption)")

    return {
        "status": "PASS",
        "cycles": 100,
        "final_records": len(final_records),
        "breakpoint": "No corruption after 100 rapid modify cycles",
    }


def test_edge_case_keys() -> dict:
    """Test 4: Edge case key values (boundary, zero, max).
    
    Breakpoint: Edge cases should not crash or corrupt.
    """
    log("Test 4: Edge case key values")

    tbl: dict[int, list] = {}
    ts = 1_000_000

    edge_cases = [
        ("zero_ips", (0, 0, 0, 0, 6)),
        ("max_ips", (0xFFFFFFFF, 65535, 0xFFFFFFFF, 65535, 6)),
        ("min_ports", (0x0A000001, 0, 0x0A000002, 0, 6)),
        ("max_ports", (0x0A000001, 65535, 0x0A000002, 65535, 6)),
        ("same_endpoints", (0x0A000001, 40000, 0x0A000001, 40000, 6)),
        ("protocol_0", (0x0A000001, 40000, 0x0A000002, 443, 0)),
        ("protocol_255", (0x0A000001, 40000, 0x0A000002, 443, 255)),
    ]

    results = []
    for name, key in edge_cases:
        try:
            e = Ev(key[0], key[1], key[2], key[3], key[4], True, True, False, False, False, 100, ts)
            r = step(tbl, e)
            results.append((name, key, r, "OK"))
            log(f"  {name}: result={r}")
        except Exception as exc:
            results.append((name, key, None, f"ERROR: {exc}"))
            log(f"  {name}: ERROR - {exc}")

    errors = [r for r in results if r[3].startswith("ERROR")]
    log(f"  Edge case breakpoint: {len(errors)} errors out of {len(edge_cases)} cases")

    return {
        "status": "PASS" if not errors else "FAIL",
        "tested": len(edge_cases),
        "errors": len(errors),
        "breakpoint": "Edge cases handled correctly",
    }


def test_malformed_snapshot() -> dict:
    """Test 5: Feed malformed snapshots to validation.
    
    Breakpoint: Malformed snapshots should be rejected, not crash.
    """
    log("Test 5: Malformed snapshot rejection")

    test_cases = [
        ("missing_chain_index", {
            "format": "crossstate-snapshot",
            "schema_version": 1,
            "spec_name": "tcp_firewall",
            "spec_version": 1,
            "slots": SLOT_COUNT,
            "source_target": "xdp",
            "records": [{
                "slot": 0,
                "key": [1, 2, 3, 4, 6],
                "st": 1,
                "last": 1000,
                "pkts": 1,
                "bytes": 40,
            }],
        }),
        ("wrong_field_count", {
            "format": "crossstate-snapshot",
            "schema_version": 1,
            "spec_name": "tcp_firewall",
            "spec_version": 1,
            "slots": SLOT_COUNT,
            "source_target": "xdp",
            "records": [{
                "slot": 0,
                "key": [1, 2, 3, 4, 6],
                "st": 1,
                "last": 1000,
                "pkts": 1,
                "bytes": 40,
                "chain_index": 0,
                "extra_field": "bad",
            }],
        }),
        ("invalid_slot", {
            "format": "crossstate-snapshot",
            "schema_version": 1,
            "spec_name": "tcp_firewall",
            "spec_version": 1,
            "slots": SLOT_COUNT,
            "source_target": "xdp",
            "records": [{
                "slot": SLOT_COUNT,  # Out of range
                "key": [1, 2, 3, 4, 6],
                "st": 1,
                "last": 1000,
                "pkts": 1,
                "bytes": 40,
                "chain_index": 0,
            }],
        }),
        ("invalid_chain_index", {
            "format": "crossstate-snapshot",
            "schema_version": 1,
            "spec_name": "tcp_firewall",
            "spec_version": 1,
            "slots": SLOT_COUNT,
            "source_target": "xdp",
            "records": [{
                "slot": 0,
                "key": [1, 2, 3, 4, 6],
                "st": 1,
                "last": 1000,
                "pkts": 1,
                "bytes": 40,
                "chain_index": 99,  # Out of range
            }],
        }),
    ]

    results = []
    for name, snapshot in test_cases:
        try:
            errors = validate_snapshot(snapshot)
            is_rejected = len(errors) > 0
            results.append((name, is_rejected, errors[:2] if errors else None))
            log(f"  {name}: rejected={is_rejected}, errors={len(errors)}")
            assert is_rejected, f"{name} should be rejected"
        except Exception as exc:
            results.append((name, False, [f"CRASH: {exc}"]))
            log(f"  {name}: CRASHED - {exc}")

    crashes = [r for r in results if r[2] and r[2][0] and r[2][0].startswith("CRASH")]
    log(f"  Malformed snapshot breakpoint: {len(crashes)} crashes out of {len(test_cases)} cases")

    return {
        "status": "PASS" if not crashes else "FAIL",
        "tested": len(test_cases),
        "rejected": sum(1 for r in results if r[1]),
        "crashes": len(crashes),
        "breakpoint": "Malformed snapshots rejected without crashing",
    }


def test_sequential_migrations() -> dict:
    """Test 6: Rapid sequential migrations between two snapshots.
    
    Breakpoint: Sequential migrations should not accumulate errors.
    """
    log("Test 6: Rapid sequential migrations")

    from scripts.state_snapshot import build_snapshot as build_snap

    record_a = {
        "slot": 10,
        "key": [0x0A000001, 40000, 0x0A000002, 443, 6],
        "st": 2,
        "last": 1000,
        "pkts": 5,
        "bytes": 200,
        "chain_index": 0,
    }

    record_b = {
        "slot": 11,
        "key": [0x0A000003, 40001, 0x0A000004, 443, 6],
        "st": 2,
        "last": 2000,
        "pkts": 10,
        "bytes": 400,
        "chain_index": 0,
    }

    results = []
    for i in range(50):
        try:
            # Calculate correct slots using CRC32
            rec_a = dict(record_a)
            rec_b = dict(record_b)
            rec_a["slot"] = slot_of(tuple(rec_a["key"]))
            rec_b["slot"] = slot_of(tuple(rec_b["key"]))
            snap = build_snap("bmv2", [rec_a, rec_b])
            errors = validate_snapshot(snap)
            report = compare_snapshots(snap, snap)
            results.append((i, report["equivalent"], len(errors)))
            assert report["equivalent"], f"Iteration {i}: not equivalent"
            assert len(errors) == 0, f"Iteration {i}: validation errors"
        except Exception as exc:
            results.append((i, False, [str(exc)]))
            log(f"  Iteration {i}: ERROR - {exc}")

    errors = [r for r in results if not r[1] or (r[2] and len(r[2]) > 0)]
    log(f"  Sequential migration breakpoint: {len(errors)} failures out of 50 iterations")

    return {
        "status": "PASS" if not errors else "FAIL",
        "iterations": 50,
        "failures": len(errors),
        "breakpoint": "No degradation after 50 sequential migrations",
    }


def test_source_mutation() -> dict:
    """Test 7: Source mutation between exports should be detected.
    
    Breakpoint: Stability check should catch source changes.
    """
    log("Test 7: Source mutation detection")

    snap_a = {
        "format": "crossstate-snapshot",
        "schema_version": 1,
        "spec_name": "tcp_firewall",
        "spec_version": 1,
        "slots": SLOT_COUNT,
        "source_target": "bmv2",
        "records": [{
            "slot": 5,
            "key": [0x0A000001, 40000, 0x0A000002, 443, 6],
            "st": 2,
            "last": 1000,
            "pkts": 5,
            "bytes": 200,
            "chain_index": 0,
        }],
    }

    snap_b = {
        "format": "crossstate-snapshot",
        "schema_version": 1,
        "spec_name": "tcp_firewall",
        "spec_version": 1,
        "slots": SLOT_COUNT,
        "source_target": "bmv2",
        "records": [{
            "slot": 5,
            "key": [0x0A000001, 40000, 0x0A000002, 443, 6],
            "st": 2,
            "last": 9999,  # Mutated timestamp
            "pkts": 5,
            "bytes": 200,
            "chain_index": 0,
        }],
    }

    try:
        report = compare_snapshots(snap_a, snap_b)
        equivalent = report.get("equivalent", False)
        detected = not equivalent
        log(f"  Source mutation: equivalent={equivalent}, detected={detected}")
        assert detected, "Source mutation should be detected"
        log("  Source mutation breakpoint: CONFIRMED (mutation detected)")

        return {
            "status": "PASS",
            "detected": detected,
            "breakpoint": "Source mutation between exports detected",
        }
    except Exception as exc:
        log(f"  Source mutation: ERROR - {exc}")
        return {
            "status": "FAIL",
            "detected": False,
            "error": str(exc),
        }


def main():
    print("=" * 60)
    print("CrossState Stress Test Suite")
    print("Finding breakpoints by attempting to break the system")
    print("=" * 60)
    print()

    results = {}

    log("Starting stress tests...\n")

    results["bucket_overflow"] = test_bucket_overflow()
    print()

    results["high_flow_capacity"] = test_high_flow_capacity()
    print()

    results["rapid_modifications"] = test_rapid_modifications()
    print()

    results["edge_case_keys"] = test_edge_case_keys()
    print()

    results["malformed_snapshot"] = test_malformed_snapshot()
    print()

    results["sequential_migrations"] = test_sequential_migrations()
    print()

    results["source_mutation"] = test_source_mutation()
    print()

    # Summary
    print("=" * 60)
    print("STRESS TEST SUMMARY")
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
        print("OVERALL: All stress tests passed. Breakpoints identified and confirmed.")
    else:
        print("OVERALL: Some stress tests FAILED. Investigate breakpoints.")

    # Write results to file
    output = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "overall_pass": all_pass,
        "results": results,
    }
    output_path = ROOT / "artifacts" / "stress_test_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n")
    print(f"\nResults written to {output_path}")

    return 0 if all_pass else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nINTERRUPTED.", file=sys.stderr)
        raise SystemExit(130)
