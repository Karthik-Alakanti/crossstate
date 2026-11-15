#!/usr/bin/env python3

import csv
import json
import subprocess
import time
import sys
from pathlib import Path

# Make the CrossState project root importable when the script
# is executed by Python through sudo using its absolute path.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import Ether, Raw, IP, TCP, sendp, sniff

from ref.model import Ev, canon, slot_of, step


ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts" / "g1"

THRIFT_PORT = 9090

HOST_MAC = "8a:e6:c2:1f:f7:28"
BMV2_MAC = "42:5d:f5:f9:83:48"

PROTO = 6
N = 65536
T_US = 30_000_000

FLAGS_INSIDE = 0x01

STATE_NAMES = {
    0: "EMPTY",
    1: "NEW",
    2: "EST",
    3: "CLOSED",
}


# ------------------------------------------------------------
# BMv2 helpers
# ------------------------------------------------------------

def cli(command: str) -> str:
    result = subprocess.run(
        [
            "simple_switch_CLI",
            "--thrift-port",
            str(THRIFT_PORT),
        ],
        input=command + "\n",
        text=True,
        capture_output=True,
        check=True,
    )

    return result.stdout


def reset_bmv2():
    cli("reset_state")


def read_register(name: str, slot: int) -> int:
    out = cli(f"register_read {name} {slot}")

    marker = f"{name}[{slot}]="

    for line in out.splitlines():
        if marker in line:
            value = line.split(marker, 1)[1].strip()
            return int(value)

    raise RuntimeError(
        f"Could not parse {name}[{slot}] from BMv2 output:\n{out}"
    )


def read_slot(slot: int):
    valid = read_register("r_valid", slot)

    if valid == 0:
        return None

    return {
        "key": (
            read_register("r_ipa", slot),
            read_register("r_pa", slot),
            read_register("r_ipb", slot),
            read_register("r_pb", slot),
            PROTO,
        ),
        "st": read_register("r_st", slot),
        "last": read_register("r_last", slot),
        "pkts": read_register("r_pkts", slot),
        "bytes": read_register("r_bytes", slot),
    }


# ------------------------------------------------------------
# Packet construction
# ------------------------------------------------------------

def make_packet(ev: Ev, pkt_id: int):
    flags = FLAGS_INSIDE if ev.inside else 0

    # CrossState shim:
    # ts_us  = 6 bytes
    # pkt_id = 4 bytes
    # flags  = 1 byte
    # inner  = 2 bytes
    shim = (
        ev.ts.to_bytes(6, "big") +
        pkt_id.to_bytes(4, "big") +
        bytes([flags]) +
        (0x0800).to_bytes(2, "big")
    )

    tcp_flags = 0

    if ev.syn:
        tcp_flags |= 0x02

    if ev.ack:
        tcp_flags |= 0x10

    if ev.fin:
        tcp_flags |= 0x01

    if ev.rst:
        tcp_flags |= 0x04

    return (
        Ether(
            src=HOST_MAC,
            dst=BMV2_MAC,
            type=0x88B5,
        )
        /
        Raw(load=shim)
        /
        IP(
            src=str(__import__("ipaddress").ip_address(ev.sip)),
            dst=str(__import__("ipaddress").ip_address(ev.dip)),
        )
        /
        TCP(
            sport=ev.sport,
            dport=ev.dport,
            flags=tcp_flags,
        )
    )


# ------------------------------------------------------------
# Wire verdict
# ------------------------------------------------------------

def send_and_capture(packet, pkt_id: int):
    captured = sniff(
        iface="cs-host",
        timeout=0.15,
        store=True,
        started_callback=lambda: sendp(
            packet,
            iface="cs-host",
            count=1,
            verbose=False,
        ),
    )

    matching = []

    for p in captured:
        if Ether not in p:
            continue

        if p[Ether].type != 0x88B5:
            continue

        raw = bytes(p)

        if len(raw) < 27:
            continue

        # Ethernet 14 + ts 6 + pkt_id 4
        observed_pkt_id = int.from_bytes(
            raw[20:24],
            "big",
        )

        if observed_pkt_id != pkt_id:
            continue

        matching.append(raw)

    if not matching:
        raise RuntimeError(
            f"No returned packet captured for pkt_id={pkt_id}"
        )

    # Last copy is the BMv2 return on the veth hairpin path.
    raw = matching[-1]

    returned_flags = raw[24]

    allow = (returned_flags >> 2) & 1

    return allow, returned_flags, raw


# ------------------------------------------------------------
# Find a CRC collision for T5
# ------------------------------------------------------------

def find_collision(base_key):
    """
    Deterministically find a distinct canonical key that maps to the
    same direct-mapped slot.

    We search the low 16 bits of both IP addresses and then both ports.
    Searching only one field is not guaranteed to produce a collision
    for a particular starting key.
    """
    target_slot = slot_of(base_key)

    ia, pa, ib, pb, proto = base_key

    # Search low 16 bits of source IP.
    ia_prefix = ia & 0xFFFF0000

    for low in range(65536):
        candidate = (
            ia_prefix | low,
            pa,
            ib,
            pb,
            proto,
        )

        if candidate == base_key:
            continue

        if canon(
            Ev(
                sip=candidate[0],
                sport=candidate[1],
                dip=candidate[2],
                dport=candidate[3],
                proto=candidate[4],
                inside=True,
                syn=True,
                ack=False,
                fin=False,
                rst=False,
                length=40,
                ts=1,
            )
        ) == base_key:
            continue

        if slot_of(candidate) == target_slot:
            return candidate

    # Search low 16 bits of destination IP.
    ib_prefix = ib & 0xFFFF0000

    for low in range(65536):
        candidate = (
            ia,
            pa,
            ib_prefix | low,
            pb,
            proto,
        )

        if candidate == base_key:
            continue

        if slot_of(candidate) == target_slot:
            return candidate

    # Search source port.
    for port in range(65536):
        candidate = (
            ia,
            port,
            ib,
            pb,
            proto,
        )

        if candidate == base_key:
            continue

        if slot_of(candidate) == target_slot:
            return candidate

    # Search destination port.
    for port in range(65536):
        candidate = (
            ia,
            pa,
            ib,
            port,
            proto,
        )

        if candidate == base_key:
            continue

        if slot_of(candidate) == target_slot:
            return candidate

    raise RuntimeError(
        f"Could not find CRC slot collision for slot {target_slot}"
    )


# ------------------------------------------------------------
# Trace definitions
# ------------------------------------------------------------

K1 = (
    577090037,
    37303,
    3639700191,
    52577,
    6,
)

K2 = (
    167772161,
    40000,
    167772162,
    443,
    6,
)

K3 = (
    167772171,
    41000,
    167772172,
    443,
    6,
)

K4 = (
    167772181,
    42000,
    167772182,
    443,
    6,
)


def ev_from_key(
    key,
    *,
    inside,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    length=40,
    ts=1_000_000,
):
    ia, pa, ib, pb, proto = key

    return Ev(
        sip=ia,
        sport=pa,
        dip=ib,
        dport=pb,
        proto=proto,
        inside=inside,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
        length=length,
        ts=ts,
    )


def build_traces():
    # T1: empty -> NEW
    t1 = [
        ev_from_key(
            K1,
            inside=True,
            syn=True,
            ts=1_000_000,
        ),
    ]

    # T2:
    # SYN creates NEW
    # inside ACK while NEW keeps NEW
    # reverse SYN+ACK establishes EST
    t2 = [
        ev_from_key(
            K2,
            inside=True,
            syn=True,
            ts=1_000_000,
        ),
        ev_from_key(
            K2,
            inside=True,
            ack=True,
            ts=1_000_001,
        ),
        ev_from_key(
            K2,
            inside=False,
            syn=True,
            ack=True,
            ts=1_000_002,
        ),
    ]

    # T3:
    # NEW -> EST -> CLOSED
    # packet after CLOSED drops
    # new SYN recreates NEW
    t3 = [
        ev_from_key(
            K3,
            inside=True,
            syn=True,
            ts=1_000_000,
        ),
        ev_from_key(
            K3,
            inside=False,
            syn=True,
            ack=True,
            ts=1_000_001,
        ),
        ev_from_key(
            K3,
            inside=True,
            ack=True,
            ts=1_000_002,
        ),
        ev_from_key(
            K3,
            inside=True,
            ack=True,
            fin=True,
            ts=1_000_003,
        ),
        ev_from_key(
            K3,
            inside=True,
            ack=True,
            ts=1_000_004,
        ),
        ev_from_key(
            K3,
            inside=True,
            syn=True,
            ts=1_000_005,
        ),
    ]

    # T4:
    # creation
    # packet > 30 s later is expired
    # initial SYN recreates the slot
    t4 = [
        ev_from_key(
            K4,
            inside=True,
            syn=True,
            ts=1_000_000,
        ),
        ev_from_key(
            K4,
            inside=False,
            ack=True,
            ts=31_000_001,
        ),
        ev_from_key(
            K4,
            inside=True,
            syn=True,
            ts=31_000_002,
        ),
    ]

    # T5 gets constructed after K4.
    return {
        "T1_NEW": t1,
        "T2_ESTABLISH": t2,
        "T3_CLOSED_REOPEN": t3,
        "T4_LAZY_EXPIRY": t4,
    }


# ------------------------------------------------------------
# Main experiment
# ------------------------------------------------------------

def main():
    ART.mkdir(parents=True, exist_ok=True)

    traces = build_traces()

    # Build T5 collision based on K1.
    collision_key = find_collision(K1)

    t5 = [
        ev_from_key(
            K1,
            inside=True,
            syn=True,
            ts=1_000_000,
        ),
        ev_from_key(
            collision_key,
            inside=True,
            syn=True,
            ts=1_000_001,
        ),
    ]

    traces["T5_COLLISION"] = t5

    all_results = []

    print("=" * 72)
    print("CROSSSTATE G1 BMv2 SUITE")
    print("=" * 72)

    print(
        f"Collision key: {collision_key}"
    )

    print(
        f"Collision slot: {slot_of(collision_key)}"
    )

    for trace_name, events in traces.items():
        print()
        print("-" * 72)
        print(trace_name)
        print("-" * 72)

        reset_bmv2()

        model_tbl = {}

        first_key = canon(events[0])
        trace_slot = slot_of(first_key)

        trace_ok = True

        for idx, ev in enumerate(events, start=1):
            oracle_verdict = step(model_tbl, ev)

            pkt = make_packet(ev, pkt_id=idx)

            bm_verdict, returned_flags, raw = send_and_capture(
                pkt,
                pkt_id=idx,
            )

            verdict_match = (
                bm_verdict == oracle_verdict
            )

            trace_ok &= verdict_match

            result = {
                "trace": trace_name,
                "event": idx,
                "slot": slot_of(canon(ev)),
                "oracle_verdict": (
                    "ALLOW" if oracle_verdict else "DROP"
                ),
                "bmv2_verdict": (
                    "ALLOW" if bm_verdict else "DROP"
                ),
                "returned_flags": returned_flags,
                "verdict_match": verdict_match,
            }

            all_results.append(result)

            print(
                f"event={idx} "
                f"slot={result['slot']} "
                f"oracle={result['oracle_verdict']} "
                f"bmv2={result['bmv2_verdict']} "
                f"match={verdict_match}"
            )

        oracle_record = model_tbl.get(trace_slot)
        bmv2_record = read_slot(trace_slot)

        if oracle_record is None:
            oracle_json = None
        else:
            oracle_json = {
                "key": list(oracle_record[0]),
                "st": oracle_record[1],
                "last": oracle_record[2],
                "pkts": oracle_record[3],
                "bytes": oracle_record[4],
            }

        record_match = True

        if oracle_json is None:
            record_match = bmv2_record is None
        else:
            if bmv2_record is None:
                record_match = False
            else:
                record_match = (
                    oracle_json["key"] == list(bmv2_record["key"])
                    and
                    oracle_json["st"] == bmv2_record["st"]
                    and
                    oracle_json["last"] == bmv2_record["last"]
                    and
                    oracle_json["pkts"] == bmv2_record["pkts"]
                    and
                    oracle_json["bytes"] == bmv2_record["bytes"]
                )

        trace_ok &= record_match

        print(
            "oracle_record =",
            oracle_json,
        )

        print(
            "bmv2_record   =",
            bmv2_record,
        )

        print(
            "record_match  =",
            record_match,
        )

        print(
            "TRACE RESULT   =",
            "PASS" if trace_ok else "FAIL",
        )

        all_results.append(
            {
                "trace": trace_name,
                "event": "FINAL_STATE",
                "slot": trace_slot,
                "oracle_record": oracle_json,
                "bmv2_record": bmv2_record,
                "record_match": record_match,
                "trace_pass": trace_ok,
            }
        )

    # --------------------------------------------------------
    # Save JSON
    # --------------------------------------------------------

    json_path = ART / "g1_results.json"

    json_path.write_text(
        json.dumps(
            {
                "collision_key": list(collision_key),
                "collision_slot": slot_of(collision_key),
                "results": all_results,
            },
            indent=2,
        )
    )

    # --------------------------------------------------------
    # Save CSV
    # --------------------------------------------------------

    csv_path = ART / "g1_results.csv"

    event_rows = [
        r for r in all_results
        if isinstance(r.get("event"), int)
    ]

    fields = [
        "trace",
        "event",
        "slot",
        "oracle_verdict",
        "bmv2_verdict",
        "returned_flags",
        "verdict_match",
    ]

    with csv_path.open(
        "w",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()

        for row in event_rows:
            writer.writerow(
                {
                    field: row.get(field)
                    for field in fields
                }
            )

    print()
    print("=" * 72)
    print("G1 SUMMARY")
    print("=" * 72)

    event_mismatches = [
        r for r in event_rows
        if not r["verdict_match"]
    ]

    trace_summaries = [
        r for r in all_results
        if r.get("event") == "FINAL_STATE"
    ]

    failed_traces = [
        r for r in trace_summaries
        if not r["trace_pass"]
    ]

    print(
        f"packet verdict mismatches = "
        f"{len(event_mismatches)}"
    )

    print(
        f"failed traces = "
        f"{len(failed_traces)} / {len(trace_summaries)}"
    )

    if not event_mismatches and not failed_traces:
        print("CROSSSTATE_G1_PASS")
    else:
        print("CROSSSTATE_G1_FAIL")


if __name__ == "__main__":
    main()
