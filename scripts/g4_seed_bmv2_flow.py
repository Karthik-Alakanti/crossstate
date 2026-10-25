#!/usr/bin/env python3
"""Create one new BMv2 flow without resetting existing firewall state."""

import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, sendp, sniff, get_if_hwaddr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import Ev, canon, slot_of
from scripts.export_bmv2_state import parse_indexed_registers
from scripts.import_xdp_state import (
    decode_current_record,
    find_map_info,
    read_raw_slot,
)
from scripts.state_snapshot import validate_snapshot

THRIFT_PORT = 9090
TX_IFACE = "cs-host"
SOURCE_IP = 0x0A630001       # 10.99.0.1
DESTINATION_IP = 0x0A630002  # 10.99.0.2
DESTINATION_PORT = 443
TIMESTAMP_US = 2_000_000_000
PACKET_ID = 0xC5000001

READ_REGISTERS = [
    "r_valid", "r_ipa", "r_pa", "r_ipb", "r_pb",
    "r_st", "r_last", "r_pkts", "r_bytes",
]


def cli(commands):
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
        input="\n".join(commands) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"BMv2 CLI failed:\n{result.stdout[-1000:]}\n"
            f"{result.stderr[-1000:]}"
        )
    return result.stdout + "\n" + result.stderr


def load_slots(path, target):
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_snapshot(snapshot)
    if errors:
        raise ValueError(f"Invalid {target} snapshot: {errors}")
    if snapshot["source_target"] != target:
        raise ValueError(
            f"Expected a {target} snapshot, got {snapshot['source_target']}."
        )
    return {record["slot"] for record in snapshot["records"]}


def bmv2_slot_is_empty(slot):
    parsed = parse_indexed_registers(
        cli([f"register_read r_valid {slot}"]),
        [("r_valid", slot)],
    )
    return parsed[("r_valid", slot)] == 0


def choose_free_flow(used_slots, xdp_map_id):
    for source_port in range(49152, 65536):
        event = Ev(
            SOURCE_IP, source_port, DESTINATION_IP, DESTINATION_PORT, 6,
            True, True, False, False, False, 40, TIMESTAMP_US,
        )
        key = canon(event)
        slot = slot_of(key)

        if slot in used_slots:
            continue
        if not bmv2_slot_is_empty(slot):
            continue

        xdp_record = decode_current_record(
            slot, read_raw_slot(xdp_map_id, slot)
        )
        if xdp_record is not None:
            continue

        return event, key, slot

    raise RuntimeError("Could not find a free slot in both live targets.")


def send_packet(event, key):
    host_mac = get_if_hwaddr("cs-host")
    switch_mac = get_if_hwaddr("cs-bmv2")

    flags = (
        event.ts.to_bytes(6, "big")
        + PACKET_ID.to_bytes(4, "big")
        + b"\x01"           # inside
        + b"\x08\x00"       # encapsulated IPv4
    )

    packet = (
        Ether(src=host_mac, dst=switch_mac, type=0x88B5)
        / Raw(load=flags)
        / IP(
            src=str(ipaddress.IPv4Address(event.sip)),
            dst=str(ipaddress.IPv4Address(event.dip)),
        )
        / TCP(sport=event.sport, dport=event.dport, flags="S")
    )

    captured = sniff(
        iface=TX_IFACE,
        timeout=0.7,
        store=True,
        started_callback=lambda: sendp(
            packet, iface=TX_IFACE, count=1, verbose=False
        ),
    )

    matches = []
    for item in captured:
        if Ether not in item or item[Ether].type != 0x88B5:
            continue
        raw = bytes(item)
        if len(raw) >= 27 and int.from_bytes(raw[20:24], "big") == PACKET_ID:
            matches.append(raw)

    if not matches:
        raise RuntimeError("No matching BMv2 response packet was captured.")

    returned_flags = matches[-1][24]
    if ((returned_flags >> 2) & 1) != 1:
        raise RuntimeError(
            f"BMv2 did not allow the SYN; returned flags=0x{returned_flags:02x}."
        )

    return returned_flags


def verify_bmv2_record(slot, key):
    requests = [
        (name, slot) for name in READ_REGISTERS
    ]
    values = parse_indexed_registers(
        cli([f"register_read {name} {slot}" for name in READ_REGISTERS]),
        requests,
    )

    actual_key = (
        values[("r_ipa", slot)],
        values[("r_pa", slot)],
        values[("r_ipb", slot)],
        values[("r_pb", slot)],
        6,
    )
    expected = {
        "r_valid": 1,
        "r_st": 1,  # NEW
        "r_last": TIMESTAMP_US,
        "r_pkts": 1,
        "r_bytes": 40,
    }

    if actual_key != key:
        raise RuntimeError(f"Stored key mismatch: {actual_key} != {key}")

    for name, expected_value in expected.items():
        actual = values[(name, slot)]
        if actual != expected_value:
            raise RuntimeError(
                f"{name}[{slot}]={actual}, expected {expected_value}."
            )

    return {
        "slot": slot,
        "key": list(key),
        "st": values[("r_st", slot)],
        "last": values[("r_last", slot)],
        "pkts": values[("r_pkts", slot)],
        "bytes": values[("r_bytes", slot)],
        "synced": values.get(("r_synced", slot), 0),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bmv2-snapshot", type=Path, required=True,
        help="Fresh snapshot of current BMv2 state.",
    )
    parser.add_argument(
        "--xdp-snapshot", type=Path,
        default=ROOT / "artifacts/state/xdp_snapshot.json",
        help="Snapshot of current XDP baseline.",
    )
    args = parser.parse_args()

    try:
        used_slots = (
            load_slots(args.bmv2_snapshot, "bmv2")
            | load_slots(args.xdp_snapshot, "xdp")
        )
        xdp_map_id = find_map_info()["id"]
        event, key, slot = choose_free_flow(used_slots, xdp_map_id)

        print("========== CONTROLLED BMv2 FLOW ==========")
        print("Selected free slot:", slot)
        print("Canonical key:", key)
        print("Timestamp:", event.ts)
        print("Sending one inside TCP SYN...")

        flags = send_packet(event, key)
        record = verify_bmv2_record(slot, key)

        print(f"Returned flags: 0x{flags:02x}")
        print("Verified BMv2 record:", json.dumps(record, sort_keys=True))
        print("Existing state was not reset.")
        print("G4_BMV2_NEW_FLOW = PASS")
        return 0

    except Exception as exc:
        print(f"G4_BMV2_NEW_FLOW = FAIL\n{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
