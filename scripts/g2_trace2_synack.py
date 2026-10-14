import time
from scapy.all import AsyncSniffer, Ether, IP, TCP, Raw, get_if_hwaddr, sendp

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"
ETHERTYPE = 0x88B5

TS_US = 1_000_001
PKT_ID = 2

# Reverse direction of the first SYN.
SRC_IP = "216.241.106.223"
DST_IP = "34.101.177.245"
SRC_PORT = 52577
DST_PORT = 37303

shim = (
    TS_US.to_bytes(6, "big")
    + PKT_ID.to_bytes(4, "big")
    + bytes([0x00])  # outside
    + (0x0800).to_bytes(2, "big")
)

pkt = (
    Ether(
        src=get_if_hwaddr(TX_IFACE),
        dst=get_if_hwaddr(RX_IFACE),
        type=ETHERTYPE,
    )
    / Raw(shim)
    / IP(src=SRC_IP, dst=DST_IP)
    / TCP(sport=SRC_PORT, dport=DST_PORT, flags="SA", seq=10, ack=2)
)

sniffer = AsyncSniffer(iface=RX_IFACE, store=True)
sniffer.start()
time.sleep(0.3)
sendp(pkt, iface=TX_IFACE, verbose=False)
time.sleep(0.6)
packets = sniffer.stop()

flags_seen = []
for p in packets:
    raw = bytes(p)
    if (
        len(raw) >= 27
        and raw[12:14] == b"\x88\xb5"
        and raw[14:20] == TS_US.to_bytes(6, "big")
        and raw[20:24] == PKT_ID.to_bytes(4, "big")
    ):
        flags_seen.append(raw[24])

print("========== G2 TRACE 2: SYN-ACK ==========")
print("Expected flags: 0x04 (ALLOW, outside)")
print("Observed flags:", [f"0x{x:02x}" for x in flags_seen])

if 0x04 in flags_seen:
    print("TRACE2_SYNACK_ALLOW = PASS")
else:
    print("TRACE2_SYNACK_ALLOW = FAIL")
