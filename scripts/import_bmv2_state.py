#!/usr/bin/env python3
"""Validated, dry-run-first import of CrossState snapshots into BMv2."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.export_bmv2_state import parse_indexed_registers
from scripts.state_snapshot import validate_snapshot

REGISTER_NAMES = [
    "r_valid",
    "r_ipa",
    "r_pa",
    "r_ipb",
    "r_pb",
    "r_st",
    "r_last",
    "r_pkts",
    "r_bytes",
    "r_synced",
]
LOGICAL_FIELDS = ("st", "last", "pkts", "bytes")
DEFAULT_SNAPSHOT = ROOT / "artifacts/state/xdp_snapshot.json"


def run_cli(commands, thrift_port):
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"BMv2 CLI exited with code {result.returncode}:\n"
            f"{result.stderr[-1500:]}"
        )

    output = result.stdout + "\n" + result.stderr
    if re.search(
        r"(?im)^.*(?:Error:|Exception:|Invalid value|Cannot find register).*$",
        output,
    ):
        raise RuntimeError(f"BMv2 CLI reported an error:\n{output[-2000:]}")

    return output


def read_slots(slots, thrift_port):
    """Read requested slots, including r_synced for safe rollback."""
    slots = sorted(set(slots))
    if not slots:
        return {}

    requests = [
        (name, slot)
        for slot in slots
        for name in REGISTER_NAMES
    ]
    output = run_cli(
        [f"register_read {name} {slot}" for name, slot in requests],
        thrift_port,
    )
    values = parse_indexed_registers(output, requests)

    result = {}
    for slot in slots:
        fields = {
            name: values[(name, slot)]
            for name in REGISTER_NAMES
        }

        if fields["r_valid"] not in (0, 1):
            raise ValueError(f"Invalid r_valid at slot {slot}.")

        if fields["r_valid"] == 0:
            result[slot] = None
            continue

        result[slot] = {
            "slot": slot,
            "key": [
                fields["r_ipa"],
                fields["r_pa"],
                fields["r_ipb"],
                fields["r_pb"],
                6,
            ],
            "st": fields["r_st"],
            "last": fields["r_last"],
            "pkts": fields["r_pkts"],
            "bytes": fields["r_bytes"],
            "synced": fields["r_synced"],
        }

    return result


def plan_import(snapshot, existing_by_slot, replace_same_key=False):
    """Create a complete import plan; no destination writes occur here."""
    plans = []
    errors = []

    for wanted in snapshot["records"]:
        slot = wanted["slot"]
        current = existing_by_slot.get(slot)

        if current is None:
            plans.append({
                "action": "insert",
                "slot": slot,
                "record": wanted,
            })
            continue

        if current["key"] != wanted["key"]:
            errors.append(
                f"Slot {slot} is occupied by a different key; "
                "different-key collisions are never overwritten."
            )
            plans.append({
                "action": "blocked_slot_conflict",
                "slot": slot,
                "record": wanted,
            })
            continue

        differences = {
            field: {
                "destination": current[field],
                "snapshot": wanted[field],
            }
            for field in LOGICAL_FIELDS
            if current[field] != wanted[field]
        }

        if not differences:
            plans.append({
                "action": "noop",
                "slot": slot,
                "record": wanted,
            })
        elif not replace_same_key:
            errors.append(
                f"Slot {slot} has the same key but different state; "
                "rerun with --replace-same-key to permit replacement."
            )
            plans.append({
                "action": "blocked_same_key_difference",
                "slot": slot,
                "record": wanted,
                "differences": differences,
            })
        else:
            plans.append({
                "action": "replace",
                "slot": slot,
                "record": wanted,
                "differences": differences,
            })

    return plans, errors


def build_write_commands(record, synced=0):
    """Write a record with valid=1 only after all fields have been set."""
    slot = record["slot"]

    return [
        f"register_write r_valid {slot} 0",
        f"register_write r_ipa {slot} {record['key'][0]}",
        f"register_write r_pa {slot} {record['key'][1]}",
        f"register_write r_ipb {slot} {record['key'][2]}",
        f"register_write r_pb {slot} {record['key'][3]}",
        f"register_write r_st {slot} {record['st']}",
        f"register_write r_last {slot} {record['last']}",
        f"register_write r_pkts {slot} {record['pkts']}",
        f"register_write r_bytes {slot} {record['bytes']}",
        f"register_write r_synced {slot} {synced}",
        f"register_write r_valid {slot} 1",
    ]


def clear_slot_commands(slot):
    # An invalid entry is logically empty; stale payload values are ignored.
    return [f"register_write r_valid {slot} 0"]


def logical_record_matches(actual, wanted):
    return (
        actual is not None
        and actual["slot"] == wanted["slot"]
        and actual["key"] == wanted["key"]
        and all(actual[field] == wanted[field] for field in LOGICAL_FIELDS)
        and actual["synced"] == 0
    )


def apply_plan(plans, previous_by_slot, thrift_port):
    """Apply inserts/replacements, verify them, and best-effort rollback."""
    changed = [
        plan for plan in plans
        if plan["action"] in {"insert", "replace"}
    ]
    applied = []

    try:
        for plan in changed:
            wanted = plan["record"]
            slot = plan["slot"]
            old = previous_by_slot[slot]

            run_cli(build_write_commands(wanted, synced=0), thrift_port)

            actual = read_slots([slot], thrift_port)[slot]
            if not logical_record_matches(actual, wanted):
                raise RuntimeError(
                    f"Post-write verification failed for slot {slot}."
                )

            applied.append(plan)

    except Exception as exc:
        rollback_errors = []

        # Include the current plan as well: the CLI may have partially written it.
        attempted = changed[:len(applied) + 1]

        for plan in reversed(attempted):
            slot = plan["slot"]
            old = previous_by_slot[slot]

            try:
                if old is None:
                    run_cli(clear_slot_commands(slot), thrift_port)
                else:
                    old_record = {
                        "slot": slot,
                        "key": old["key"],
                        "st": old["st"],
                        "last": old["last"],
                        "pkts": old["pkts"],
                        "bytes": old["bytes"],
                    }
                    run_cli(
                        build_write_commands(
                            old_record, synced=old["synced"]
                        ),
                        thrift_port,
                    )

                restored = read_slots([slot], thrift_port)[slot]
                if old is None:
                    if restored is not None:
                        raise RuntimeError("Slot remained valid.")
                elif (
                    restored is None
                    or restored["key"] != old["key"]
                    or any(
                        restored[field] != old[field]
                        for field in LOGICAL_FIELDS
                    )
                    or restored["synced"] != old["synced"]
                ):
                    raise RuntimeError("Restored record did not match.")
            except Exception as rollback_exc:
                rollback_errors.append(
                    f"slot {slot}: {rollback_exc}"
                )

        message = f"Import failed and rollback was attempted: {exc}"
        if rollback_errors:
            message += "\nROLLBACK ERRORS:\n" + "\n".join(rollback_errors)
        raise RuntimeError(message) from exc

    return len(applied)


def main():
    parser = argparse.ArgumentParser(
        description="Import a validated CrossState state snapshot into BMv2."
    )
    parser.add_argument(
        "snapshot",
        nargs="?",
        type=Path,
        default=DEFAULT_SNAPSHOT,
    )
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument(
        "--replace-same-key",
        action="store_true",
        help="Permit replacing existing state for the same flow key.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform writes. Without this flag the command is dry-run only.",
    )
    args = parser.parse_args()

    if not 1 <= args.thrift_port <= 65535:
        print("Invalid Thrift port.", file=sys.stderr)
        return 2

    snapshot_path = args.snapshot
    if not snapshot_path.is_absolute():
        snapshot_path = ROOT / snapshot_path

    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        errors = validate_snapshot(snapshot)
        if errors:
            raise ValueError(
                "Snapshot validation failed:\n- " + "\n- ".join(errors)
            )

        if not snapshot["records"]:
            print("Snapshot contains no records; nothing to import.")
            return 0

        slots = [record["slot"] for record in snapshot["records"]]
        previous = read_slots(slots, args.thrift_port)

        plans, planning_errors = plan_import(
            snapshot,
            previous,
            replace_same_key=args.replace_same_key,
        )

    except Exception as exc:
        print(f"BMV2_STATE_IMPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    counts = {}
    for plan in plans:
        counts[plan["action"]] = counts.get(plan["action"], 0) + 1

    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"========== BMv2 STATE IMPORT: {mode} ==========")
    print(f"Snapshot source: {snapshot['source_target']}")
    print(f"Records inspected: {len(snapshot['records'])}")
    for action in sorted(counts):
        print(f"{action}: {counts[action]}")

    if planning_errors:
        print(f"Preflight errors: {len(planning_errors)}")
        for error in planning_errors:
            print("BLOCKED:", error)
        print("No writes performed.")
        print("BMV2_STATE_IMPORT = BLOCKED")
        return 2

    if not args.apply:
        print("No writes performed. Review the plan; use --apply to write.")
        print("BMV2_STATE_IMPORT = DRY_RUN_PASS")
        return 0

    try:
        count = apply_plan(plans, previous, args.thrift_port)
    except Exception as exc:
        print(f"BMV2_STATE_IMPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    print(f"Records written and verified: {count}")
    print(
        "Imported entries were marked r_synced=0; "
        "shadow synchronization is not being claimed."
    )
    print("BMV2_STATE_IMPORT = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
