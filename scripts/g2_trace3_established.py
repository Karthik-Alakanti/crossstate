import time
from scapy.all import (
    AsyncSniffer, Ether, IP, TCP, Raw,
    get_if_hwaddr, sendp
)

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"

TS_US = 1_000_002
PKT_ID = 3

SRC_IP = "34.101.177.245"
DST_IP = "216.241.106.223"
SRC_PORT = 37303
DST_PORT = 52577

shim = (
    TS_US.to_bytes(6, "big")
    + PKT_ID.to_bytes(4, "big")
    + bytes([0x01])  # inside
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
    / TCP(
        sport=SRC_PORT,
        dport=DST_PORT,
        flags="A",
        seq=2,
        ack=11,
    )
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

print("========== G2 TRACE 3: ESTABLISHED ACK ==========")
print("Expected flags: 0x05 (inside + ALLOW)")
print("Observed flags:", [f"0x{x:02x}" for x in observed])
print("TRACE3_ESTABLISHED_ALLOW =", "PASS" if 0x05 in observed else "FAIL")
