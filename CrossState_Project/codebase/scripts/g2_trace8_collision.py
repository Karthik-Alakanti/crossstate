import time
import ipaddress

from ref.model import Ev, canon, slot_of
from scapy.all import (
    AsyncSniffer, Ether, IP, TCP, Raw,
    get_if_hwaddr, sendp
)

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"

TS_US = 31_000_006
PKT_ID = 8

# Different flow, chosen to collide with slot 30468.
SRC_IP = "34.101.48.89"
DST_IP = "216.241.106.223"
SRC_PORT = 37303
DST_PORT = 52577

ev = Ev(
    int(ipaddress.IPv4Address(SRC_IP)), SRC_PORT,
    int(ipaddress.IPv4Address(DST_IP)), DST_PORT,
    6, True, True, False, False, False, 40, TS_US
)

key = canon(ev)
slot = slot_of(key)

print("========== G2 TRACE 8: COLLISION ==========")
print("Collision key:", key)
print("Calculated slot:", slot)
print("Expected slot: 30468")

if slot != 30468:
    raise SystemExit("FAIL: collision key does not map to slot 30468")

shim = (
    TS_US.to_bytes(6, "big")
    + PKT_ID.to_bytes(4, "big")
    + b"\x01"
    + (0x0800).to_bytes(2, "big")
)

pkt = (
    Ether(
        src=get_if_hwaddr(TX_IFACE),
        dst=get_if_hwaddr(RX_IFACE),
        type=0x88B5,
    )
    / Raw(shim)
    / IP(src=SRC_IP, dst=DST_IP)
    / TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=100)
)

sniffer = AsyncSniffer(iface=RX_IFACE, store=True)
sniffer.start()
time.sleep(0.3)
sendp(pkt, iface=TX_IFACE, verbose=False)
time.sleep(0.6)
packets = sniffer.stop()

observed = []
for p in packets:
    raw = bytes(p)
    if (
        len(raw) >= 27
        and raw[12:14] == b"\x88\xb5"
        and raw[14:20] == TS_US.to_bytes(6, "big")
        and raw[20:24] == PKT_ID.to_bytes(4, "big")
    ):
        observed.append(raw[24])

print("Expected flags: 0x01 (DROP)")
print("Observed flags:", [f"0x{x:02x}" for x in observed])

passed = 0x01 in observed
print("TRACE8_COLLISION_REJECT =", "PASS" if passed else "FAIL")
