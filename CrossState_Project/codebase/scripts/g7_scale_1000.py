#!/usr/bin/env python3
"""CrossState G7 scale test: 1,000 new TCP flows across BMv2 and XDP.

Preserves existing state. Creates half the new flows through BMv2,
checkpoints them to XDP, updates them on XDP, then creates the other half
through XDP, checkpoints them to BMv2, updates them on BMv2, and performs
a final checkpoint back to XDP.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import AsyncSniffer, Ether, IP, TCP, Raw, get_if_hwaddr, sendp
from ref.model import Ev, canon, slot_of
from scripts import sync_state

THRIFT_PORT = 9090
ETHERTYPE = 0x88B5
IP_SRC_BASE = int(ipaddress.IPv4Address("10.200.0.1"))
IP_DST = "10.201.0.1"
IP_DST_INT = int(ipaddress.IPv4Address(IP_DST))
DST_PORT = 443
SRC_PORT_BASE = 20000
TCP_BYTES = 40
DEFAULT_BATCH_SIZE = 50


def log(message: str) -> None:
    print(message, flush=True)


def run_checked(
    command: list[str],
    *,
    label: str,
    log_path: Path | None = None,
) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )
    combined = (result.stdout or "") + (result.stderr or "")

    if log_path is not None:
        log_path.write_text(combined)

    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)

    if result.returncode:
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}. "
            + (f"See {log_path}" if log_path else "")
        )

    return combined


def preflight() -> None:
    if os.geteuid() != 0:
        raise RuntimeError(
            "Run as root. Use: sudo env PYTHONPATH=\"$PWD:$VENV_SITE\" "
            "\"$PY\" scripts/g7_scale_1000.py --traffic-quiesced"
        )

    for iface in ("cs-host", "cs-bmv2", "cs-xdp-host", "cs-xdp"):
        subprocess.run(
            ["ip", "link", "show", "dev", iface],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

    ss = subprocess.run(
        ["ss", "-lnt"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout

    if ":9090" not in ss:
        raise RuntimeError("BMv2 Thrift port 9090 is not listening.")

    net = subprocess.run(
        ["bpftool", "net", "show"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout

    if "cs-xdp" not in net:
        raise RuntimeError("No XDP attachment was found on cs-xdp.")

    maps = subprocess.run(
        ["bpftool", "map", "show"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout

    if "flow_state" not in maps:
        raise RuntimeError("The XDP flow_state map was not found.")

    import scapy.all  # noqa: F401

    log("PREFLIGHT = PASS (interfaces, BMv2 Thrift, XDP attachment, map, Scapy)")


def export_one(target: str, outpath: Path) -> dict[str, Any]:
    return sync_state.export_state(target, outpath, THRIFT_PORT)


def export_pair(
    outdir: Path,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], Path, Path, dict[str, Any]]:
    bpath = outdir / f"{label}_bmv2.json"
    xpath = outdir / f"{label}_xdp.json"
    report_path = outdir / f"{label}_comparison.json"

    bstate = export_one("bmv2", bpath)
    xstate = export_one("xdp", xpath)
    report = sync_state.compare(bpath, xpath, report_path)

    return bstate, xstate, bpath, xpath, report


def records_by_slot(snapshot: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {int(r["slot"]): r for r in snapshot["records"]}


def snapshot_slots(snapshot: dict[str, Any]) -> set[int]:
    return set(records_by_slot(snapshot))


def logical_snapshot_assertion(
    bstate: dict[str, Any],
    xstate: dict[str, Any],
    report: dict[str, Any],
    label: str,
) -> None:
    if not report.get("equivalent", False):
        raise RuntimeError(
            f"{label}: BMv2 and XDP snapshots are not equivalent."
        )

    if len(bstate["records"]) != len(xstate["records"]):
        raise RuntimeError(f"{label}: record counts differ.")


def assert_flow_record(
    snapshot: dict[str, Any],
    case: dict[str, Any],
    *,
    packets: int,
    byte_count: int,
    last: int,
    target: str,
) -> None:
    rec = records_by_slot(snapshot).get(case["slot"])

    if rec is None:
        raise RuntimeError(
            f"{target}: flow {case['index']} missing at slot {case['slot']}."
        )

    if list(rec["key"]) != list(case["key"]):
        raise RuntimeError(
            f"{target}: key mismatch at slot {case['slot']}: {rec.get('key')}"
        )

    expected = {
        "st": 1,
        "last": last,
        "pkts": packets,
        "bytes": byte_count,
    }
    actual = {k: int(rec[k]) for k in expected}

    if actual != expected:
        raise RuntimeError(
            f"{target}: flow {case['index']} state mismatch. "
            f"Expected {expected}, got {actual}."
        )


def assert_baseline_preserved(
    baseline: dict[str, Any],
    final_bmv2: dict[str, Any],
    final_xdp: dict[str, Any],
) -> None:
    """Ensure every pre-existing logical record survives unchanged."""
    baseline_records = records_by_slot(baseline)
    final_b = records_by_slot(final_bmv2)
    final_x = records_by_slot(final_xdp)
    fields = ("key", "st", "last", "pkts", "bytes")

    for slot, before in baseline_records.items():
        for target, after_records in (
            ("BMv2", final_b),
            ("XDP", final_x),
        ):
            after = after_records.get(slot)

            if after is None:
                raise RuntimeError(
                    f"Baseline flow at slot {slot} disappeared from {target}."
                )

            for field in fields:
                old_value = (
                    list(before[field])
                    if field == "key"
                    else int(before[field])
                )
                new_value = (
                    list(after[field])
                    if field == "key"
                    else int(after[field])
                )

                if old_value != new_value:
                    raise RuntimeError(
                        f"Baseline flow at slot {slot} changed on {target}: "
                        f"{field} {old_value!r} -> {new_value!r}."
                    )

    log(
        f"Baseline preservation: verified {len(baseline_records)} "
        "original records on both targets."
    )


def assert_cases(
    snapshot: dict[str, Any],
    cases: list[dict[str, Any]],
    *,
    stage: str,
    packets: int,
    byte_count: int,
    time_field: str,
    target: str,
) -> None:
    for case in cases:
        assert_flow_record(
            snapshot,
            case,
            packets=packets,
            byte_count=byte_count,
            last=int(case[time_field]),
            target=target,
        )

    log(f"{stage}: {target} verified {len(cases)} generated flow records.")


def make_cases(
    count: int,
    occupied_slots: set[int],
    *,
    base_ts: int,
) -> list[dict[str, Any]]:
    """Generate deterministic keys with unique, unoccupied CRC32 slots."""
    used_slots = set(occupied_slots)
    cases: list[dict[str, Any]] = []
    candidate = 0

    while len(cases) < count:
        src_int = IP_SRC_BASE + candidate

        if src_int >= 0xFFFFFFFF:
            raise RuntimeError("Ran out of source IPv4 addresses.")

        src_ip = str(ipaddress.IPv4Address(src_int))
        src_port = SRC_PORT_BASE + candidate

        if src_port > 65535:
            raise RuntimeError("Ran out of source TCP ports.")

        event = Ev(
            src_int,
            src_port,
            IP_DST_INT,
            DST_PORT,
            6,
            True,
            True,
            False,
            False,
            False,
            TCP_BYTES,
            0,
        )

        key = canon(event)
        slot = int(slot_of(key))

        if slot not in used_slots:
            group = 1 if len(cases) < count // 2 else 2
            local_index = (
                len(cases)
                if group == 1
                else len(cases) - count // 2
            )

            syn_ts = (
                base_ts + candidate
                if group == 1
                else base_ts + 20_000 + candidate
            )

            ack_ts = (
                base_ts + 10_000 + candidate
                if group == 1
                else base_ts + 30_000 + candidate
            )

            cases.append({
                "index": len(cases) + 1,
                "group": group,
                "creation_target": "bmv2" if group == 1 else "xdp",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": IP_DST,
                "dst_port": DST_PORT,
                "key": list(key),
                "slot": slot,
                "syn_ts": syn_ts,
                "ack_ts": ack_ts,
                "syn_pkt_id": (
                    0x51000000 + local_index
                    if group == 1
                    else 0x53000000 + local_index
                ),
                "ack_pkt_id": (
                    0x52000000 + local_index
                    if group == 1
                    else 0x54000000 + local_index
                ),
            })

            used_slots.add(slot)

        candidate += 1

    return cases


def target_interfaces(target: str) -> tuple[str, str, str]:
    if target == "bmv2":
        return "cs-host", "cs-bmv2", "cs-host"

    if target == "xdp":
        return "cs-xdp-host", "cs-xdp", "cs-xdp"

    raise ValueError(target)


def make_packet(
    target: str,
    case: dict[str, Any],
    *,
    packet_kind: str,
) -> tuple[Any, int, int]:
    tx, peer, _capture = target_interfaces(target)

    if packet_kind == "syn":
        ts = int(case["syn_ts"])
        pkt_id = int(case["syn_pkt_id"])
        tcp_flags = "S"
    elif packet_kind == "ack":
        ts = int(case["ack_ts"])
        pkt_id = int(case["ack_pkt_id"])
        tcp_flags = "A"
    else:
        raise ValueError(packet_kind)

    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + b"\x01\x08\x00"
    )

    packet = (
        Ether(
            src=get_if_hwaddr(tx),
            dst=get_if_hwaddr(peer),
            type=ETHERTYPE,
        )
        / Raw(load=shim)
        / IP(src=case["src_ip"], dst=case["dst_ip"])
        / TCP(
            sport=int(case["src_port"]),
            dport=int(case["dst_port"]),
            flags=tcp_flags,
            seq=pkt_id & 0xFFFFFFFF,
            ack=(pkt_id + 1) & 0xFFFFFFFF,
        )
    )

    return packet, pkt_id, ts


def send_batch(
    target: str,
    cases: list[dict[str, Any]],
    *,
    packet_kind: str,
    batch_size: int,
    inter_packet_seconds: float,
) -> int:
    """Send real datapath packets in bounded batches and validate responses."""
    tx, _peer, capture = target_interfaces(target)
    total_sent = 0

    for offset in range(0, len(cases), batch_size):
        batch = cases[offset:offset + batch_size]
        packets = []
        expected: dict[int, int] = {}

        for case in batch:
            packet, pkt_id, ts = make_packet(
                target,
                case,
                packet_kind=packet_kind,
            )
            packets.append(packet)
            expected[pkt_id] = ts

        sniffer = AsyncSniffer(iface=capture, store=True)
        sniffer.start()
        time.sleep(0.12)

        try:
            sendp(
                packets,
                iface=tx,
                inter=inter_packet_seconds,
                verbose=False,
            )
            time.sleep(0.30)
            captured = sniffer.stop()
        except Exception:
            try:
                sniffer.stop()
            except Exception:
                pass
            raise

        observed: dict[int, list[int]] = {}

        for frame in captured:
            raw = bytes(frame)

            if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
                continue

            seen_ts = int.from_bytes(raw[14:20], "big")
            seen_id = int.from_bytes(raw[20:24], "big")

            if seen_id in expected and expected[seen_id] == seen_ts:
                observed.setdefault(seen_id, []).append(raw[24])

        missing = sorted(set(expected) - set(observed))

        bad = {
            pkt_id: flags
            for pkt_id, flags in observed.items()
            if (flags[-1] & 0x04) == 0
        }

        if missing or bad:
            raise RuntimeError(
                f"{target.upper()} {packet_kind.upper()} batch failed. "
                f"Missing responses={len(missing)} "
                f"(first={missing[:8]}), "
                f"not-allowed={len(bad)} "
                f"(first={list(bad.items())[:8]}). "
                "The script stopped without retrying packets, to avoid "
                "silently incrementing flow counters twice."
            )

        total_sent += len(batch)

        log(
            f"{target.upper()} {packet_kind.upper()}: "
            f"{total_sent}/{len(cases)} packets accepted."
        )

    return total_sent


def checkpoint(
    outdir: Path,
    direction: str,
    ordinal: int,
) -> None:
    log(f"\n========== CHECKPOINT {ordinal}: {direction} ==========")

    logfile = outdir / f"checkpoint_{ordinal}_{direction}.log"
    state_dir = ROOT / "artifacts" / "state"
    previous_audits = set(state_dir.glob("sync_*"))

    run_checked(
        [
            sys.executable,
            str(ROOT / "scripts" / "sync_state.py"),
            "--direction",
            direction,
            "--apply",
            "--traffic-quiesced",
            "--thrift-port",
            str(THRIFT_PORT),
        ],
        label=f"checkpoint {direction}",
        log_path=logfile,
    )

    new_audits = [
        p for p in state_dir.glob("sync_*")
        if p not in previous_audits
    ]

    if new_audits:
        audit_dir = (
            outdir
            / "checkpoint_audits"
            / f"checkpoint_{ordinal}"
        )
        audit_dir.mkdir(parents=True, exist_ok=True)

        for audit_path in new_audits:
            if audit_path.is_file():
                shutil.copy2(
                    audit_path,
                    audit_dir / audit_path.name,
                )

    log(
        f"CHECKPOINT_{ordinal}_"
        f"{direction.upper().replace('-', '_')} = PASS"
    )


def save_manifest(
    outdir: Path,
    cases: list[dict[str, Any]],
) -> None:
    path = outdir / "flow_manifest.csv"

    fields = [
        "index",
        "group",
        "creation_target",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "slot",
        "key",
        "syn_ts",
        "syn_pkt_id",
        "ack_ts",
        "ack_pkt_id",
    ]

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for case in cases:
            row = {k: case[k] for k in fields if k in case}
            row["key"] = json.dumps(case["key"])
            writer.writerow(row)


def metric_count(
    report: dict[str, Any],
    *names: str,
) -> int:
    """Accept either list-valued comparator details or numeric summaries."""
    for name in names:
        if name not in report:
            continue

        value = report[name]

        if isinstance(value, bool):
            return int(value)

        if isinstance(value, (int, float)):
            return int(value)

        if isinstance(value, (list, tuple, set, dict)):
            return len(value)

    return 0


def write_summary(
    outdir: Path,
    *,
    requested_flows: int,
    baseline_count: int,
    final_count: int,
    final_report: dict[str, Any],
    checkpoints: int,
) -> None:
    summary = {
        "experiment": (
            "CrossState G7 1000-flow "
            "bidirectional datapath/checkpoint test"
        ),
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "requested_new_flows": requested_flows,
        "flows_created_through_bmv2": requested_flows // 2,
        "flows_created_through_xdp": requested_flows // 2,
        "baseline_records_preserved": baseline_count,
        "final_bmv2_records": final_count,
        "final_xdp_records": final_count,
        "final_exact_matches": metric_count(
            final_report,
            "exact_matches",
        ),
        "final_differing_records": metric_count(
            final_report,
            "different_values",
            "differing_records",
            "different_records",
            "value_mismatches",
        ),
        "final_bmv2_only": metric_count(
            final_report,
            "left_only_slots",
            "bmv2_only",
            "source_only_slots",
        ),
        "final_xdp_only": metric_count(
            final_report,
            "right_only_slots",
            "xdp_only",
            "destination_only_slots",
        ),
        "final_logically_equivalent": bool(
            final_report.get("equivalent", False)
        ),
        "successful_checkpoint_operations": checkpoints,
        "direct_map_capacity": 65536,
        "final_map_occupancy_percent": round(
            final_count / 65536 * 100.0,
            6,
        ),
        "packet_types": {
            "new_flow_creation": "TCP SYN",
            "post_migration_update": "TCP ACK",
            "expected_final_state": "NEW",
            "expected_final_packets_per_generated_flow": 2,
            "expected_final_bytes_per_generated_flow": 80,
        },
        "limitations": [
            "This is a controlled software datapath test using "
            "BMv2 and XDP on veth interfaces.",
            "It does not measure throughput, latency, line rate, "
            "or migration duration.",
            "It does not establish hardware-switch or "
            "production-scale performance.",
        ],
    }

    (outdir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--flows",
        type=int,
        default=1000,
        help=(
            "Number of NEW flows to create in addition to existing "
            "baseline (default: 1000)."
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "scale_1000",
        help=(
            "Run-artifact directory "
            "(default: artifacts/scale_1000)."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Packets per Scapy batch (default: 50).",
    )

    parser.add_argument(
        "--inter-packet-ms",
        type=float,
        default=0.5,
        help="Spacing between packets in a batch, in milliseconds.",
    )

    parser.add_argument(
        "--traffic-quiesced",
        action="store_true",
        help=(
            "Acknowledge this isolated test runtime has no concurrent "
            "traffic during checkpoints."
        ),
    )

    args = parser.parse_args()

    if not args.traffic_quiesced:
        parser.error(
            "This experiment applies checkpoints. Add --traffic-quiesced "
            "only when no other traffic is using these test datapaths."
        )

    if args.flows < 2 or args.flows % 2:
        parser.error("--flows must be an even integer of at least 2.")

    if not 1 <= args.batch_size <= 250:
        parser.error("--batch-size must be between 1 and 250.")

    if args.inter_packet_ms < 0:
        parser.error("--inter-packet-ms cannot be negative.")

    preflight()

    stamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )

    outdir = (
        args.output_dir.expanduser().resolve()
        / f"run_{stamp}"
    )
    outdir.mkdir(parents=True, exist_ok=False)

    log(f"Output directory: {outdir}")

    # Preserve and validate the current baseline. Never reset either target.
    b0, x0, _bp0, _xp0, baseline_report = export_pair(
        outdir,
        "00_baseline",
    )

    logical_snapshot_assertion(
        b0,
        x0,
        baseline_report,
        "baseline",
    )

    baseline_count = len(b0["records"])
    occupied = snapshot_slots(b0) | snapshot_slots(x0)

    log(f"Baseline records preserved: {baseline_count}")

    base_ts = max(
        [
            int(r["last"])
            for r in b0["records"] + x0["records"]
        ] + [1_000_000]
    ) + 10_000

    if base_ts + 100_000 >= (1 << 48):
        raise RuntimeError(
            "No safe u48 timestamp range remains for this test."
        )

    all_cases = make_cases(
        args.flows,
        occupied,
        base_ts=base_ts,
    )

    first = [c for c in all_cases if c["group"] == 1]
    second = [c for c in all_cases if c["group"] == 2]

    save_manifest(outdir, all_cases)

    # Phase 1: create the first half through BMv2.
    log("\n========== PHASE 1A: CREATE FLOWS THROUGH BMv2 ==========")

    send_batch(
        "bmv2",
        first,
        packet_kind="syn",
        batch_size=args.batch_size,
        inter_packet_seconds=args.inter_packet_ms / 1000.0,
    )

    b1, x1, _bp1, _xp1, _r1 = export_pair(
        outdir,
        "01_after_bmv2_syn",
    )

    if len(b1["records"]) != baseline_count + len(first):
        raise RuntimeError(
            "BMv2 record count did not increase by the first batch size."
        )

    if len(x1["records"]) != baseline_count:
        raise RuntimeError(
            "XDP changed before the first checkpoint."
        )

    assert_cases(
        b1,
        first,
        stage="BMv2 SYN creation",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="BMv2",
    )

    # Phase 1B: migrate BMv2 -> XDP and verify.
    checkpoint(outdir, "bmv2-to-xdp", 1)

    b2, x2, _bp2, _xp2, r2 = export_pair(
        outdir,
        "02_after_bmv2_to_xdp",
    )

    logical_snapshot_assertion(
        b2,
        x2,
        r2,
        "after BMv2 -> XDP",
    )

    assert_cases(
        b2,
        first,
        stage="After BMv2 -> XDP",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="BMv2",
    )

    assert_cases(
        x2,
        first,
        stage="After BMv2 -> XDP",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="XDP",
    )

    # Phase 1C: process the migrated flows on XDP, then checkpoint back.
    log("\n========== PHASE 1C: UPDATE MIGRATED FLOWS THROUGH XDP ==========")

    send_batch(
        "xdp",
        first,
        packet_kind="ack",
        batch_size=args.batch_size,
        inter_packet_seconds=args.inter_packet_ms / 1000.0,
    )

    x_ack_path = outdir / "03_xdp_after_ack_group1.json"
    x_ack = export_one("xdp", x_ack_path)

    assert_cases(
        x_ack,
        first,
        stage="XDP ACK after migration",
        packets=2,
        byte_count=80,
        time_field="ack_ts",
        target="XDP",
    )

    checkpoint(outdir, "xdp-to-bmv2", 2)

    b3, x3, _bp3, _xp3, r3 = export_pair(
        outdir,
        "04_after_xdp_to_bmv2_group1",
    )

    logical_snapshot_assertion(
        b3,
        x3,
        r3,
        "after XDP -> BMv2 group 1",
    )

    assert_cases(
        b3,
        first,
        stage="After XDP -> BMv2 group 1",
        packets=2,
        byte_count=80,
        time_field="ack_ts",
        target="BMv2",
    )

    assert_cases(
        x3,
        first,
        stage="After XDP -> BMv2 group 1",
        packets=2,
        byte_count=80,
        time_field="ack_ts",
        target="XDP",
    )

    # Phase 2: create the remaining half through XDP.
    log("\n========== PHASE 2A: CREATE FLOWS THROUGH XDP ==========")

    send_batch(
        "xdp",
        second,
        packet_kind="syn",
        batch_size=args.batch_size,
        inter_packet_seconds=args.inter_packet_ms / 1000.0,
    )

    b4, x4, _bp4, _xp4, _r4 = export_pair(
        outdir,
        "05_after_xdp_syn_group2",
    )

    if len(x4["records"]) != baseline_count + args.flows:
        raise RuntimeError(
            "XDP record count did not increase by the total new flow count."
        )

    if len(b4["records"]) != baseline_count + len(first):
        raise RuntimeError(
            "BMv2 changed before the second checkpoint."
        )

    assert_cases(
        x4,
        second,
        stage="XDP SYN creation",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="XDP",
    )

    # Phase 2B: migrate the second half XDP -> BMv2.
    checkpoint(outdir, "xdp-to-bmv2", 3)

    b5, x5, _bp5, _xp5, r5 = export_pair(
        outdir,
        "06_after_xdp_to_bmv2_all",
    )

    logical_snapshot_assertion(
        b5,
        x5,
        r5,
        "after XDP -> BMv2 group 2",
    )

    assert_cases(
        b5,
        second,
        stage="After XDP -> BMv2 group 2",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="BMv2",
    )

    assert_cases(
        x5,
        second,
        stage="After XDP -> BMv2 group 2",
        packets=1,
        byte_count=40,
        time_field="syn_ts",
        target="XDP",
    )

    # Phase 2C: process those migrated flows on BMv2, then checkpoint back.
    log("\n========== PHASE 2C: UPDATE MIGRATED FLOWS THROUGH BMv2 ==========")

    send_batch(
        "bmv2",
        second,
        packet_kind="ack",
        batch_size=args.batch_size,
        inter_packet_seconds=args.inter_packet_ms / 1000.0,
    )

    b_ack_path = outdir / "07_bmv2_after_ack_group2.json"
    b_ack = export_one("bmv2", b_ack_path)

    assert_cases(
        b_ack,
        second,
        stage="BMv2 ACK after migration",
        packets=2,
        byte_count=80,
        time_field="ack_ts",
        target="BMv2",
    )

    checkpoint(outdir, "bmv2-to-xdp", 4)

    # Final all-record reconciliation.
    bf, xf, bfp, xfp, rf = export_pair(
        outdir,
        "08_final",
    )

    logical_snapshot_assertion(
        bf,
        xf,
        rf,
        "final",
    )

    final_count = baseline_count + args.flows

    if (
        len(bf["records"]) != final_count
        or len(xf["records"]) != final_count
    ):
        raise RuntimeError(
            f"Expected {final_count} records on each target; got "
            f"BMv2={len(bf['records'])}, XDP={len(xf['records'])}."
        )

    for case in first:
        for snap, target in (
            (bf, "BMv2"),
            (xf, "XDP"),
        ):
            assert_flow_record(
                snap,
                case,
                packets=2,
                byte_count=80,
                last=int(case["ack_ts"]),
                target=target,
            )

    for case in second:
        for snap, target in (
            (bf, "BMv2"),
            (xf, "XDP"),
        ):
            assert_flow_record(
                snap,
                case,
                packets=2,
                byte_count=80,
                last=int(case["ack_ts"]),
                target=target,
            )

    assert_baseline_preserved(b0, bf, xf)

    write_summary(
        outdir,
        requested_flows=args.flows,
        baseline_count=baseline_count,
        final_count=final_count,
        final_report=rf,
        checkpoints=4,
    )

    log("\n" + "=" * 72)
    log("CROSSSTATE G7 SCALE TEST = PASS")
    log(f"New datapath-created flows: {args.flows}")
    log(f"Created through BMv2: {len(first)}")
    log(f"Created through XDP: {len(second)}")
    log(f"Baseline records preserved: {baseline_count}")
    log(f"Final BMv2 records: {len(bf['records'])}")
    log(f"Final XDP records: {len(xf['records'])}")
    log(f"Exact logical matches: {metric_count(rf, 'exact_matches')}")
    log("Final packet/byte counters: 2 packets / 80 bytes per generated flow")
    log("Checkpoint operations: 4 (both directions exercised)")
    log(f"Artifacts: {outdir}")
    log("=" * 72)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(
            "\nINTERRUPTED. No reset was issued. Inspect the last exported "
            "snapshots and checkpoint log before rerunning.",
            file=sys.stderr,
        )
        raise SystemExit(130)
    except Exception as exc:
        print(
            f"\nG7 SCALE TEST FAILED: {exc}",
            file=sys.stderr,
        )
        print(
            "No automatic reset or cleanup was attempted. Preserve the "
            "artifacts and inspect target snapshots before rerunning.",
            file=sys.stderr,
        )
        raise SystemExit(1)
