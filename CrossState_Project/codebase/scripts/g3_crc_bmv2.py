#!/usr/bin/env python3

import ipaddress
import json
import random
import re
import subprocess
import sys
import time
from pathlib import Path

from scapy.all import Ether, IP, TCP, Raw, sendp, sniff, get_if_hwaddr

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import Ev, canon, key_bytes, slot_of

THRIFT_PORT = 9090
TX_IFACE = "cs-host"

BASE_TS = 4_000_000
BASE_PKT_ID = 50_000
NUM_TESTS = 20

REGISTER_NAMES = [
    "r_valid", "r_ipa", "r_pa", "r_ipb", "r_pb",
    "r_st", "r_last", "r_pkts", "r_bytes",
]

# Avoid the previously used flow and make collisions explicit.
EXISTING_SLOT = 30468
EXISTING_KEY = (577090037, 37303, 3639700191, 52577, 6)


def cli(command):
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
        input=command + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout + "\n" + result.stderr


def canonical_key(values):
    ia, pa, ib, pb, proto = values
    event = Ev(
        ia, pa, ib, pb, proto,
        True, True, False, False, False,
        40, 0,
    )
    return canon(event)


def make_cases():
    with (ROOT / "artifacts/crc_vectors.json").open() as f:
        vectors = json.load(f)

    rng = random.Random(20261015)
    cases = []
    seen_keys = set()
    seen_slots = {}

    def try_add(raw_key, source):
        key = canonical_key(raw_key)
        slot = slot_of(key)

        if key in seen_keys:
            return False
        if slot in seen_slots and seen_slots[slot] != key:
            return False
        if slot == EXISTING_SLOT and key != EXISTING_KEY:
            return False

        seen_keys.add(key)
        seen_slots[slot] = key
        cases.append({"key": key, "slot": slot, "source": source})
        return True

    for row in vectors:
        try_add(row["key"], "crc_vector")

    # Add deterministic supplemental vectors if canonicalization or slot
    # collisions reduce the number of usable vector rows.
    while len(cases) < NUM_TESTS:
        ia = rng.getrandbits(32)
        ib = rng.getrandbits(32)
        pa = rng.getrandbits(16)
        pb = rng.getrandbits(16)
        if (ia, pa) == (ib, pb):
            continue
        try_add((ia, pa, ib, pb, 6), "supplemental")

    return cases


def read_slot(slot):
    commands = "\n".join(
        f"register_read {name} {slot}"
        for name in REGISTER_NAMES
    )
    output = cli(commands)

    values = {}
    for name in REGISTER_NAMES:
        marker = f"{name}[{slot}]="
        for line in output.splitlines():
            if marker in line:
                values[name] = int(line.split(marker, 1)[1].strip())
                break

    missing = [n for n in REGISTER_NAMES if n not in values]
    if missing:
        raise RuntimeError(
            f"Could not read registers {missing} at slot {slot}:\n{output}"
        )

    if values["r_valid"] == 0:
        return None

    return {
        "key": (
            values["r_ipa"],
            values["r_pa"],
            values["r_ipb"],
            values["r_pb"],
            6,
        ),
        "st": values["r_st"],
        "last": values["r_last"],
        "pkts": values["r_pkts"],
        "bytes": values["r_bytes"],
    }


def send_and_capture(packet, pkt_id):
    captured = sniff(
        iface=TX_IFACE,
        timeout=0.5,
        store=True,
        started_callback=lambda: sendp(
            packet, iface=TX_IFACE, count=1, verbose=False
        ),
    )

    matching = []
    for p in captured:
        if Ether not in p or p[Ether].type != 0x88B5:
            continue

        raw = bytes(p)
        if len(raw) < 27:
            continue

        seen_id = int.from_bytes(raw[20:24], "big")
        if seen_id == pkt_id:
            matching.append(raw)

    if not matching:
        return None

    # Original transmission followed by BMv2 hairpin return.
    raw = matching[-1]
    return raw[24]


def main():
    cases = make_cases()

    # Validate each selected test key before touching BMv2.
    for case in cases:
        key = case["key"]
        ev = Ev(
            key[0], key[1], key[2], key[3], key[4],
            True, True, False, False, False, 40, BASE_TS,
        )
        assert canon(ev) == key
        assert slot_of(key) == case["slot"]
        assert len(key_bytes(key)) == 13

    print("========== BMv2 RUNTIME CRC TEST ==========")
    print(f"Cases: {len(cases)}")
    print(f"Thrift port: {THRIFT_PORT}")

    host_mac = get_if_hwaddr("cs-host")
    bmv2_mac = get_if_hwaddr("cs-bmv2")

    print("\nResetting BMv2 state...")
    cli("reset_state")
    time.sleep(0.2)

    rows = []

    for i, case in enumerate(cases):
        key = case["key"]
        slot = case["slot"]
        ts = BASE_TS + i
        pkt_id = BASE_PKT_ID + i

        ia, pa, ib, pb, proto = key
        shim = (
            ts.to_bytes(6, "big")
            + pkt_id.to_bytes(4, "big")
            + b"\x01"
            + b"\x08\x00"
        )

        packet = (
            Ether(src=host_mac, dst=bmv2_mac, type=0x88B5)
            / Raw(load=shim)
            / IP(
                src=str(ipaddress.IPv4Address(ia)),
                dst=str(ipaddress.IPv4Address(ib)),
            )
            / TCP(sport=pa, dport=pb, flags="S")
        )

        try:
            returned_flags = send_and_capture(packet, pkt_id)
            actual = read_slot(slot)
            expected = {
                "key": key,
                "st": 1,
                "last": ts,
                "pkts": 1,
                "bytes": 40,
            }

            wire_ok = (
                returned_flags is not None
                and ((returned_flags >> 2) & 1) == 1
            )
            record_ok = actual == expected
            passed = wire_ok and record_ok

            row = {
                "index": i + 1,
                "source": case["source"],
                "key": list(key),
                "key_bytes": key_bytes(key).hex(),
                "expected_slot": slot,
                "returned_flags": returned_flags,
                "wire_allow": wire_ok,
                "expected_record": {
                    **expected,
                    "key": list(key),
                },
                "actual_record": (
                    {**actual, "key": list(actual["key"])}
                    if actual is not None else None
                ),
                "record_match": record_ok,
                "pass": passed,
            }
        except Exception as exc:
            row = {
                "index": i + 1,
                "key": list(key),
                "expected_slot": slot,
                "pass": False,
                "error": repr(exc),
            }

        rows.append(row)
        print(
            f"{i+1:02d}. slot={slot:5d} "
            f"wire={'PASS' if row.get('wire_allow') else 'FAIL'} "
            f"record={'PASS' if row.get('record_match') else 'FAIL'} "
            f"overall={'PASS' if row['pass'] else 'FAIL'}"
        )

    result_dir = ROOT / "artifacts" / "g3a"
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / "g3_crc_bmv2.json"

    report = {
        "test": "BMv2 CRC slot and state-record validation",
        "target": "BMv2 simple_switch_grpc / P4 v1model",
        "vectors": len(cases),
        "passed": sum(bool(row["pass"]) for row in rows),
        "failed": sum(not row["pass"] for row in rows),
        "result": "PASS" if all(row["pass"] for row in rows) else "FAIL",
        "cases": rows,
    }
    result_path.write_text(json.dumps(report, indent=2) + "\n")

    print("\n========== SUMMARY ==========")
    print(f"Cases: {len(rows)}")
    print(f"Passed: {report['passed']}")
    print(f"Failed: {report['failed']}")
    print(f"Report: {result_path.relative_to(ROOT)}")
    print("G3A_BMV2_CRC =", report["result"])

    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
