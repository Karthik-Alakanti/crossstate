import time
from scapy.all import AsyncSniffer, Ether, IP, TCP, Raw, get_if_hwaddr, sendp

TX_IFACE = "cs-xdp-host"
CAPTURE_IFACE = "cs-xdp"
ETHERTYPE = 0x88B5

TS_US = 1_000_000
PKT_ID = 1

SRC_IP = "34.101.177.245"
DST_IP = "216.241.106.223"
SRC_PORT = 37303
DST_PORT = 52577

shim = (
    TS_US.to_bytes(6, "big")
    + PKT_ID.to_bytes(4, "big")
    + bytes([0x01])
    + (0x0800).to_bytes(2, "big")
)

pkt = (
    Ether(
        src=get_if_hwaddr(TX_IFACE),
        dst=get_if_hwaddr(CAPTURE_IFACE),
        type=ETHERTYPE,
    )
    / Raw(shim)
    / IP(src=SRC_IP, dst=DST_IP)
    / TCP(sport=SRC_PORT, dport=DST_PORT, flags="S", seq=1)
)

print("========== G2 XDP SYN TRACE ==========")
print(f"Transmit interface: {TX_IFACE}")
print(f"Capture interface: {CAPTURE_IFACE}")
print("Expected slot: 30468")
print("Expected decision: ALLOW (flags 0x05)")

sniffer = AsyncSniffer(iface=CAPTURE_IFACE, store=True)
sniffer.start()
time.sleep(0.3)
sendp(pkt, iface=TX_IFACE, verbose=False)
time.sleep(0.7)
packets = sniffer.stop()

observed = []
for p in packets:
    raw = bytes(p)
    if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
        continue
    if raw[14:20] != TS_US.to_bytes(6, "big"):
        continue
    if raw[20:24] != PKT_ID.to_bytes(4, "big"):
        continue
    observed.append(raw[24])

print("Observed matching frame flags:", [f"0x{x:02x}" for x in observed])

if 0x05 in observed:
    print("TRACE1_RETURNED_ALLOW = PASS")
else:
    print("TRACE1_RETURNED_ALLOW = NOT CONFIRMED")
