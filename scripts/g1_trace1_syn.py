#!/usr/bin/env python3

import json
import ipaddress
import threading
import time
import sys
from pathlib import Path

# Make the CrossState project root importable even when this
# script is executed via sudo using an absolute path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scapy.all import Ether, IP, TCP, Raw, sendp, sniff

from ref.model import Ev, canon, slot_of, step

# ------------------------------------------------------------
# Use the first published CrossState CRC vector.
# ------------------------------------------------------------
with open("artifacts/crc_vectors.json", "r") as f:
    vectors = json.load(f)

v = vectors[0]

key = v["key"]
expected_slot = v["slot"]

ipa, pa, ipb, pb, proto = key

assert proto == 6

src_ip = str(ipaddress.ip_address(ipa))
dst_ip = str(ipaddress.ip_address(ipb))

# First hand trace event:
# protected side -> outside side, initial SYN.
ev = Ev(
    sip=ipa,
    sport=pa,
    dip=ipb,
    dport=pb,
    proto=6,
    inside=True,
    syn=True,
    ack=False,
    fin=False,
    rst=False,
    length=40,          # IPv4 + TCP, no payload
    ts=1_000_000,
)

# Python oracle
tbl = {}
expected_verdict = step(tbl, ev)
expected_record = tbl.get(expected_slot)

print("=== CROSSSTATE G1 TRACE 1 ===")
print(f"src       = {src_ip}:{pa}")
print(f"dst       = {dst_ip}:{pb}")
print(f"proto     = {proto}")
print(f"slot      = {expected_slot}")
print(f"vector_slot_matches = {expected_slot == slot_of(canon(ev))}")
print(f"expected_verdict     = {'ALLOW' if expected_verdict else 'DROP'}")
print(f"expected_record      = {expected_record}")

# CrossState shim:
# ts_us  : 48-bit
# pkt_id : 32-bit
# flags  : 8-bit
#   b0 = inside
#   b1 = shadow
#   b2 = allow
#   b3 = skipped
# inner   : 16-bit EtherType
ts_us = 1_000_000
pkt_id = 1
flags = 0x01
inner = 0x0800

shim = (
    ts_us.to_bytes(6, "big") +
    pkt_id.to_bytes(4, "big") +
    bytes([flags]) +
    inner.to_bytes(2, "big")
)

eth = Ether(
    src="8a:e6:c2:1f:f7:28",   # cs-host
    dst="42:5d:f5:f9:83:48",   # cs-bmv2
    type=0x88B5,
)

pkt = (
    eth /
    Raw(load=shim) /
    IP(src=src_ip, dst=dst_ip) /
    TCP(sport=pa, dport=pb, flags="S")
)

captured = []

def capture():
    captured.extend(
        sniff(
            iface="cs-host",
            timeout=3,
            store=True,
        )
    )

t = threading.Thread(target=capture, daemon=True)
t.start()

time.sleep(0.3)

sendp(
    pkt,
    iface="cs-host",
    verbose=False,
)

t.join()

# Keep only the returned CrossState EtherType packet.
returned = [
    p for p in captured
    if Ether in p and p[Ether].type == 0x88B5
]

print(f"crossstate_packets   = {len(returned)}")

for i, p in enumerate(returned):
    print(
        f"packet[{i}] "
        f"src={p[Ether].src} "
        f"dst={p[Ether].dst} "
        f"len={len(bytes(p))}"
    )

# The actual BMv2 hairpin return must be addressed TO cs-host.
host_mac = "8a:e6:c2:1f:f7:28"

if len(returned) < 2:
    print("ERROR: expected original + BMv2 return packet")
else:
    # On this controlled veth hairpin path, Scapy sees:
    #   returned[0] = transmitted packet
    #   returned[-1] = BMv2 return packet
    #
    # Ethernet MAC addresses are intentionally unchanged by the
    # current P4 implementation, so MAC direction cannot identify
    # the return packet.

    original = returned[0]
    wire_return = returned[-1]

    print(
        f"original_flags       = 0x{bytes(original)[24]:02x}"
    )

    raw = bytes(wire_return)

    # Ethernet = 14 bytes
    # Shim = 6-byte ts_us + 4-byte pkt_id + 1-byte flags + 2-byte inner
    # flags therefore starts at byte 14 + 6 + 4 = 24.
    returned_flags = raw[24]

    print(f"returned_flags       = 0x{returned_flags:02x}")
    print(f"allow_bit            = {(returned_flags >> 2) & 1}")
    print(f"returned_len         = {len(raw)}")
    print(f"returned_hex         = {raw.hex()}")

    actual_verdict = (returned_flags >> 2) & 1

    print(
        f"verdict_match        = "
        f"{actual_verdict == expected_verdict}"
    )

print("TRACE1_SEND_DONE")
