#!/usr/bin/env python3
"""Randomized packet-level differential test: XDP vs ref/model.py."""

import argparse
import ipaddress
import json
import random
import struct
import subprocess
import time
from collections import defaultdict

from scapy.all import AsyncSniffer, Ether, IP, TCP, Raw, get_if_hwaddr, sendp
from ref.model import Ev, ALLOW, canon, key_bytes, slot_of, step

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"
ETHERTYPE = 0x88B5
BASE_TS = 1_000_000_000
BASE_PKT_ID = 1_000_000
BATCH_SIZE = 250


def bpftool_json(args):
    return json.loads(
        subprocess.check_output(["bpftool", "-j", *args], text=True)
    )


def decode_bpf_bytes(value):
    """Decode raw byte arrays as emitted by bpftool JSON."""
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, int):
                out.append(item)
            else:
                out.append(int(str(item), 16))
        return bytes(out)

    if isinstance(value, str):
        tokens = value.split()
        if len(tokens) > 1:
            return bytes(int(token, 16) for token in tokens)

        compact = value.strip()
        if compact.startswith("0x"):
            compact = compact[2:]
        return bytes.fromhex(compact)

    raise ValueError(f"Unsupported byte representation: {type(value).__name__}")


def make_flows(count, rng):
    """Create distinct client/server five-tuples."""
    flows = []
    for i in range(count):
        client_ip = 0x0A140001 + i       # 10.20.0.x and onward
        server_ip = 0xC6336401 + i       # 198.51.100.x and onward
        client_port = rng.randint(20000, 65000)
        server_port = 80 + (i % 10000)
        flows.append((client_ip, client_port, server_ip, server_port))
    return flows


def choose_event_flags(rng):
    """Mix handshake, established, termination and arbitrary flags."""
    r = rng.random()

    if r < 0.20:
        return True, True, False, False, False       # inside SYN
    if r < 0.36:
        return False, True, True, False, False       # outside SYN-ACK
    if r < 0.62:
        return rng.choice([True, False]), False, True, False, False
    if r < 0.74:
        return rng.choice([True, False]), False, False, True, False
    if r < 0.82:
        return rng.choice([True, False]), False, False, False, True

    return (
        rng.choice([True, False]),
        rng.choice([True, False]),
        rng.choice([True, False]),
        rng.choice([True, False]),
        rng.choice([True, False]),
    )


def make_packet(flow, inside, syn, ack, fin, rst, ts, pkt_id,
                host_mac, xdp_mac):
    client_ip, client_port, server_ip, server_port = flow

    if inside:
        sip, sport = client_ip, client_port
        dip, dport = server_ip, server_port
    else:
        sip, sport = server_ip, server_port
        dip, dport = client_ip, client_port

    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + bytes([0x01 if inside else 0x00])
        + b"\x08\x00"
    )

    tcp_flags = (
        (0x02 if syn else 0)
        | (0x10 if ack else 0)
        | (0x01 if fin else 0)
        | (0x04 if rst else 0)
    )

    return (
        Ether(src=host_mac, dst=xdp_mac, type=ETHERTYPE)
        / Raw(shim)
        / IP(
            src=str(ipaddress.IPv4Address(sip)),
            dst=str(ipaddress.IPv4Address(dip)),
        )
        / TCP(
            sport=sport,
            dport=dport,
            flags=tcp_flags,
            seq=(pkt_id & 0xFFFFFFFF),
            ack=((pkt_id + 1) & 0xFFFFFFFF),
        )
    )


def lookup_record(map_id, slot):
    key = struct.pack("<I", slot)
    result = bpftool_json([
        "map", "lookup", "id", str(map_id),
        "key", "hex", *[f"{b:02x}" for b in key],
    ])
    return result.get("value", result)


def record_matches(record, expected):
    """Compare a 40-byte BPF struct with one reference-model record."""
    if isinstance(record, dict):
        stored_key = record.get("key", [])
        if isinstance(stored_key, list):
            stored_key = bytes(
                int(v, 0) if isinstance(v, str) else v
                for v in stored_key
            )
        state = int(record["st"])
        valid = int(record["valid"])
        last = int(record["last"])
        pkts = int(record["pkts"])
        byte_count = int(record["bytes"])
    else:
        raw = decode_bpf_bytes(record)
        if len(raw) != 40:
            raise ValueError(f"Expected 40-byte state record, got {len(raw)}")
        stored_key = raw[:13]
        state = raw[13]
        valid = raw[14]
        last = int.from_bytes(raw[16:24], "little")
        pkts = int.from_bytes(raw[24:32], "little")
        byte_count = int.from_bytes(raw[32:40], "little")

    if expected is None:
        return valid == 0

    key, st, ts, packets, byte_count_expected = expected
    return (
        stored_key == key_bytes(key)
        and state == st
        and valid == 1
        and last == ts
        and pkts == packets
        and byte_count == byte_count_expected
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=1000)
    parser.add_argument("--flows", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20261015)
    args = parser.parse_args()

    if args.packets < 1 or args.flows < 1:
        raise SystemExit("--packets and --flows must be positive")

    for iface in (TX_IFACE, RX_IFACE):
        subprocess.check_call(
            ["ip", "link", "show", "dev", iface],
            stdout=subprocess.DEVNULL,
        )

    maps = bpftool_json(["map", "show"])
    matching_maps = [m for m in maps if m.get("name") == "flow_state"]
    if not matching_maps:
        raise SystemExit("flow_state map not found: attach XDP first")
    map_id = matching_maps[0]["id"]

    rng = random.Random(args.seed)
    flows = make_flows(args.flows, rng)
    reference_state = {}
    touched_slots = set()
    expected_flags = {}
    observed_flags = defaultdict(list)

    host_mac = get_if_hwaddr(TX_IFACE)
    xdp_mac = get_if_hwaddr(RX_IFACE)

    def on_packet(packet):
        raw = bytes(packet)
        if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
            return

        pkt_id = int.from_bytes(raw[20:24], "big")
        if pkt_id in expected_flags:
            observed_flags[pkt_id].append(raw[24])

    sniffer = AsyncSniffer(
        iface=RX_IFACE,
        store=False,
        prn=on_packet,
    )
    sniffer.start()
    time.sleep(0.3)

    print("========== RANDOMIZED XDP DIFFERENTIAL TEST ==========")
    print(f"Packets: {args.packets}, flows: {args.flows}, seed: {args.seed}")
    print("Timestamp gaps include occasional jumps beyond the idle timeout.")

    ts = BASE_TS
    sent = 0
    t0 = time.monotonic()

    try:
        for start in range(0, args.packets, BATCH_SIZE):
            batch = []
            stop = min(start + BATCH_SIZE, args.packets)

            for i in range(start, stop):
                if i > 0 and i % 257 == 0:
                    ts += 30_000_001 + rng.randint(0, 1000)
                else:
                    ts += rng.randint(1, 1000)

                flow = rng.choice(flows)
                inside, syn, ack, fin, rst = choose_event_flags(rng)
                client_ip, client_port, server_ip, server_port = flow

                if inside:
                    sip, sport, dip, dport = (
                        client_ip, client_port, server_ip, server_port
                    )
                else:
                    sip, sport, dip, dport = (
                        server_ip, server_port, client_ip, client_port
                    )

                event = Ev(
                    sip, sport, dip, dport, 6,
                    inside, syn, ack, fin, rst, 40, ts,
                )

                verdict = step(reference_state, event)
                slot = slot_of(canon(event))
                touched_slots.add(slot)

                pkt_id = BASE_PKT_ID + i
                expected_flags[pkt_id] = (
                    (0x01 if inside else 0x00)
                    | (0x04 if verdict == ALLOW else 0x00)
                )

                batch.append(
                    make_packet(
                        flow, inside, syn, ack, fin, rst, ts, pkt_id,
                        host_mac, xdp_mac,
                    )
                )

            sendp(batch, iface=TX_IFACE, inter=0, verbose=False)
            sent += len(batch)

            if sent % 5000 == 0 or sent == args.packets:
                print(f"Sent {sent}/{args.packets}", flush=True)

            time.sleep(0.003)

        time.sleep(1.0)
    finally:
        sniffer.stop()

    packet_mismatches = []
    missing = 0
    duplicates = 0

    for pkt_id, expected in expected_flags.items():
        got = observed_flags.get(pkt_id, [])
        if len(got) == 0:
            missing += 1
        elif len(got) != 1:
            duplicates += 1
        elif got[0] != expected:
            packet_mismatches.append((pkt_id, expected, got[0]))

    state_mismatches = []
    for slot in sorted(touched_slots):
        actual = lookup_record(map_id, slot)
        expected = reference_state.get(slot)

        try:
            match = record_matches(actual, expected)
        except Exception as exc:
            match = False
            detail = f"decode error: {exc}"
        else:
            detail = "state differs"

        if not match:
            state_mismatches.append((slot, expected, detail))

    elapsed = time.monotonic() - t0
    print("\n========== SUMMARY ==========")
    print(f"Packets sent:              {sent}")
    print(f"Packets observed:           {sum(len(v) for v in observed_flags.values())}")
    print(f"Missing packet IDs:         {missing}")
    print(f"Duplicate packet IDs:       {duplicates}")
    print(f"Decision/flag mismatches:   {len(packet_mismatches)}")
    print(f"Touched slots checked:      {len(touched_slots)}")
    print(f"Final state mismatches:     {len(state_mismatches)}")
    print(f"Elapsed seconds:            {elapsed:.2f}")

    if packet_mismatches:
        print("\nFirst packet mismatches (id, expected_flags, actual_flags):")
        for row in packet_mismatches[:10]:
            print(row)

    if state_mismatches:
        print("\nFirst state mismatches (slot, expected_record, detail):")
        for row in state_mismatches[:10]:
            print(row)

    passed = (
        sent == args.packets
        and missing == 0
        and duplicates == 0
        and len(packet_mismatches) == 0
        and len(state_mismatches) == 0
    )
    print("\nG2_RANDOM_DIFFERENTIAL =", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
