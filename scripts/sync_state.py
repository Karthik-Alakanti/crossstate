#!/usr/bin/env python3
"""Quiesced, bidirectional CrossState checkpoint synchronization."""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.state_snapshot import validate_snapshot
from scripts import import_bmv2_state as bm
from scripts import import_xdp_state as xd

PYTHON = sys.executable
STATE_DIR = ROOT / "artifacts" / "state"


def run_tool(label, command):
    print(f"\n========== {label} ==========")
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}"
        )
    return result.stdout


def export_state(target, output, thrift_port):
    script = ROOT / "scripts" / (
        "export_bmv2_state.py" if target == "bmv2"
        else "export_xdp_state.py"
    )
    command = [PYTHON, str(script), "--output", str(output)]
    if target == "bmv2":
        command += ["--thrift-port", str(thrift_port)]
    run_tool(f"EXPORT {target.upper()}", command)

    snapshot = json.loads(output.read_text())
    errors = validate_snapshot(snapshot)
    if errors:
        raise RuntimeError(f"Invalid {target} snapshot: {errors}")
    if snapshot["source_target"] != target:
        raise RuntimeError("Exporter returned the wrong source_target.")
    return snapshot


def compare(left, right, report_path):
    script = ROOT / "scripts" / "compare_state_snapshots.py"
    run_tool(
        "COMPARE STATE",
        [
            PYTHON, str(script), str(left), str(right),
            "--output", str(report_path)
        ],
    )
    return json.loads(report_path.read_text())


def import_state(source, destination, snapshot_path, apply, thrift_port):
    script = ROOT / "scripts" / (
        "import_bmv2_state.py" if destination == "bmv2"
        else "import_xdp_state.py"
    )

    command = [PYTHON, str(script), str(snapshot_path), "--replace-same-key"]
    if destination == "bmv2":
        command += ["--thrift-port", str(thrift_port)]
    if apply:
        command.append("--apply")

    mode = "APPLY IMPORT" if apply else "IMPORT DRY RUN"
    run_tool(f"{mode}: {source.upper()} -> {destination.upper()}", command)


def set_xdp_ready(slots, ready):
    info = xd.find_map_info()
    map_id = info["id"]
    value = 1 if ready else 0

    for slot in slots:
        raw = bytearray(xd.read_raw_slot(map_id, slot))
        if len(raw) != 40:
            raise RuntimeError(f"Unexpected XDP record size at slot {slot}.")
        if ready and xd.decode_current_record(slot, raw) is None:
            raise RuntimeError(f"Cannot mark invalid XDP slot {slot} ready.")

        raw[15] = value
        xd.update_raw_slot(map_id, slot, bytes(raw))

    for slot in slots:
        raw = xd.read_raw_slot(map_id, slot)
        if raw[15] != value:
            raise RuntimeError(f"XDP readiness verification failed at {slot}.")


def set_bmv2_ready(slots, ready, thrift_port):
    value = 1 if ready else 0
    commands = [f"register_write r_synced {slot} {value}" for slot in slots]

    if commands:
        bm.run_cli(commands, thrift_port)

    states = bm.read_slots(slots, thrift_port)
    for slot in slots:
        record = states.get(slot)
        if ready and record is None:
            raise RuntimeError(f"Cannot mark invalid BMv2 slot {slot} ready.")
        if record is not None and record["synced"] != value:
            raise RuntimeError(
                f"BMv2 readiness verification failed at slot {slot}."
            )


def set_ready(target, slots, ready, thrift_port):
    if target == "xdp":
        set_xdp_ready(slots, ready)
    else:
        set_bmv2_ready(slots, ready, thrift_port)


def fail_closed(target, slots, thrift_port):
    print("\nWARNING: synchronization was not verified.")
    print("Attempting to mark destination records unready.")
    print("Logical state rollback is NOT performed; partial imports may remain.")
    try:
        set_ready(target, slots, False, thrift_port)
        print("FAIL_CLOSED_READINESS = PASS")
    except Exception as exc:
        print(f"FAIL_CLOSED_READINESS = ERROR: {exc}")


def validate_preflight(pre):
    """Reject destination-only records and same-slot key conflicts."""
    destination_only = pre.get("right_only_slots", [])
    if destination_only:
        raise RuntimeError(
            "Destination contains records absent from the authoritative "
            f"source at slots {destination_only[:20]}. "
            "No synchronization writes were performed."
        )

    if pre.get("slot_conflicts"):
        raise RuntimeError(
            "Same-slot different-key conflicts detected. "
            "No synchronization writes were performed."
        )

    return destination_only


def verify_source_stability(
    source, source_path, source_after_path, report_path, thrift_port
):
    """Re-export the authoritative source and verify it did not change."""
    export_state(source, source_after_path, thrift_port)
    stability = compare(source_path, source_after_path, report_path)

    if not stability.get("equivalent", False):
        raise RuntimeError(
            "Authoritative source changed during synchronization. "
            "Destination will be marked unready."
        )

    return stability


def main():
    parser = argparse.ArgumentParser(
        description="Quiesced BMv2/XDP checkpoint synchronization."
    )
    parser.add_argument(
        "--direction",
        required=True,
        choices=("bmv2-to-xdp", "xdp-to-bmv2"),
    )
    parser.add_argument("--apply", action="store_true",
                        help="Perform synchronization; otherwise dry-run.")
    parser.add_argument(
        "--traffic-quiesced", action="store_true",
        help="Acknowledge that traffic is paused for the entire apply operation."
    )
    parser.add_argument("--thrift-port", type=int, default=9090)
    args = parser.parse_args()

    if args.apply and not args.traffic_quiesced:
        parser.error("--apply requires --traffic-quiesced.")

    source, destination = args.direction.split("-to-")
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    prefix = STATE_DIR / f"sync_{args.direction}_{stamp}"

    phase_seconds: dict[str, float] = {}

    def timed(label, fn):
        t0 = time.perf_counter()
        result = fn()
        phase_seconds[label] = time.perf_counter() - t0
        return result

    source_path = Path(f"{prefix}_source.json")
    source_after_path = Path(f"{prefix}_source_after.json")
    source_stability_report = Path(f"{prefix}_source_stability.json")
    before_path = Path(f"{prefix}_destination_before.json")
    after_path = Path(f"{prefix}_destination_after.json")
    final_path = Path(f"{prefix}_destination_final.json")
    pre_report = Path(f"{prefix}_preflight.json")
    post_report = Path(f"{prefix}_verification.json")
    final_report = Path(f"{prefix}_final.json")

    print("=" * 65)
    print("CROSSSTATE CHECKPOINT SYNCHRONIZATION")
    print("=" * 65)
    print("Direction:", args.direction)
    print("Mode:", "APPLY" if args.apply else "DRY RUN")
    print("Traffic quiesced acknowledgement:", args.traffic_quiesced)

    source_snapshot = timed(
        "export_source",
        lambda: export_state(source, source_path, args.thrift_port),
    )
    destination_snapshot = timed(
        "export_destination",
        lambda: export_state(destination, before_path, args.thrift_port),
    )

    source_slots = {r["slot"] for r in source_snapshot["records"]}
    destination_slots = {
        r["slot"] for r in destination_snapshot["records"]
    }

    pre = timed(
        "compare_preflight",
        lambda: compare(source_path, before_path, pre_report),
    )

    # Refuse automatic deletion of destination-only records and
    # same-slot key conflicts.
    destination_only = validate_preflight(pre)

    print("\nSource records:", len(source_slots))
    print("Destination records:", len(destination_slots))
    print("Source-only slots to insert:", len(pre.get("left_only_slots", [])))
    print("Destination-only slots:", len(destination_only))

    # Preview first, including all importer collision checks.
    timed(
        "plan_dry_run_import",
        lambda: import_state(
            source, destination, source_path, False, args.thrift_port
        ),
    )

    if not args.apply:
        print("\nSYNC_DRY_RUN_PASS")
        print("No state or readiness flags were changed.")
        print("Review the plan, then rerun with --apply --traffic-quiesced.")
        return 0

    affected_slots = sorted(source_slots | destination_slots)

    try:
        timed(
            "apply_import",
            lambda: import_state(
                source, destination, source_path, True, args.thrift_port
            ),
        )

        # Export and compare before declaring anything synchronized.
        after_snapshot = timed(
            "export_after",
            lambda: export_state(destination, after_path, args.thrift_port),
        )
        verified = timed(
            "verify_compare",
            lambda: compare(source_path, after_path, post_report),
        )

        if not verified.get("equivalent", False):
            raise RuntimeError(
                "Post-import snapshot equivalence failed. "
                "Destination will be marked unready."
            )

        if len(after_snapshot["records"]) != len(source_slots):
            raise RuntimeError("Unexpected destination record count.")

        # Detect source changes during the import before declaring the
        # destination synchronized. Traffic must remain quiesced.
        timed(
            "stability_re_export",
            lambda: verify_source_stability(
                source,
                source_path,
                source_after_path,
                source_stability_report,
                args.thrift_port,
            ),
        )
        print("\\nAuthoritative source stability: PASS")

        # Mark readiness only after exact logical equivalence.
        timed(
            "mark_readiness",
            lambda: set_ready(
                destination, sorted(source_slots), True, args.thrift_port
            ),
        )

        # Export once more to confirm readiness marking did not alter
        # logical state.
        final_snapshot = timed(
            "final_export",
            lambda: export_state(destination, final_path, args.thrift_port),
        )
        final = timed(
            "final_compare",
            lambda: compare(source_path, final_path, final_report),
        )

        if not final.get("equivalent", False):
            raise RuntimeError(
                "Final comparison failed after readiness marking."
            )

        # Verify every readiness marker independently.
        if destination == "xdp":
            info = xd.find_map_info()
            for slot in sorted(source_slots):
                raw = xd.read_raw_slot(info["id"], slot)
                if raw[14] != 1 or raw[15] != 1:
                    raise RuntimeError(
                        f"XDP slot {slot} is not valid and synchronized."
                    )
        else:
            states = bm.read_slots(
                sorted(source_slots), args.thrift_port
            )
            for slot in sorted(source_slots):
                if states[slot] is None or states[slot]["synced"] != 1:
                    raise RuntimeError(
                        f"BMv2 slot {slot} is not synchronized."
                    )

        audit = {
            "protocol": "CrossState quiesced checkpoint synchronization",
            "direction": args.direction,
            "source_records": len(source_slots),
            "destination_records": len(final_snapshot["records"]),
            "equivalent": True,
            "readiness_marked": True,
            "synced_records": len(source_slots),
            "traffic_quiesced_acknowledged": True,
            "continuous_replication": False,
            "source_snapshot": str(source_path),
            "source_after_snapshot": str(source_after_path),
            "source_stability_report": str(source_stability_report),
            "source_stable": True,
            "destination_snapshot": str(final_path),
            "comparison": str(final_report),
            "phase_seconds": phase_seconds,
            "created_utc": stamp,
        }
        audit_path = Path(f"{prefix}_audit.json")
        audit_path.write_text(json.dumps(audit, indent=2) + "\n")

        print("\n" + "=" * 65)
        print("CROSSSTATE SYNCHRONIZATION COMPLETE")
        print("=" * 65)
        print("Records synchronized:", len(source_slots))
        print("Exact state equivalence: PASS")
        print("Destination readiness markers: PASS")
        print("Audit report:", audit_path)
        print("CHECKPOINT_SYNC = PASS")
        print(
            "NOTE: This is a quiesced checkpoint, not continuous "
            "live replication."
        )
        return 0

    except Exception:
        fail_closed(destination, affected_slots, args.thrift_port)
        raise


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"\nSYNC_ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
