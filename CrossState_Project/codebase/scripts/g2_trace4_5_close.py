import time
from scapy.all import (
    AsyncSniffer, Ether, IP, TCP, Raw,
    get_if_hwaddr, sendp
)

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"
SRC_IP, DST_IP = "34.101.177.245", "216.241.106.223"
SPORT, DPORT = 37303, 52577

host_mac = get_if_hwaddr(TX_IFACE)
xdp_mac = get_if_hwaddr(RX_IFACE)

def make_packet(ts, pkt_id, tcp_flags):
    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + b"\x01"  # inside
        + (0x0800).to_bytes(2, "big")
    )

    return (
        Ether(src=host_mac, dst=xdp_mac, type=0x88B5)
        / Raw(shim)
        / IP(src=SRC_IP, dst=DST_IP)
        / TCP(
            sport=SPORT, dport=DPORT,
            flags=tcp_flags, seq=2, ack=11
        )
    )

tests = [
    (1_000_003, 4, "FA", 0x05, "FIN closes established flow"),
    (1_000_004, 5, "A",  0x01, "ACK after closure is dropped"),
]

sniffer = AsyncSniffer(iface=RX_IFACE, store=True)
sniffer.start()
time.sleep(0.3)

for ts, pkt_id, flags, expected, description in tests:
    sendp(
        make_packet(ts, pkt_id, flags),
        iface=TX_IFACE,
        verbose=False,
    )
    time.sleep(0.25)

time.sleep(0.3)
packets = sniffer.stop()

seen = {}
for pkt in packets:
    raw = bytes(pkt)
    if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
        continue
    ts = int.from_bytes(raw[14:20], "big")
    pkt_id = int.from_bytes(raw[20:24], "big")
    if pkt_id in (4, 5):
        seen[pkt_id] = raw[24]

print("========== G2 TRACES 4–5 ==========")
all_pass = True

for ts, pkt_id, tcp_flags, expected, description in tests:
    observed = seen.get(pkt_id)
    passed = observed == expected
    all_pass &= passed
    print(f"\nTrace {pkt_id}: {description}")
    print(f"  Expected flags: 0x{expected:02x}")
    print(
        "  Observed flags:",
        f"0x{observed:02x}" if observed is not None else "NOT OBSERVED",
    )
    print(f"  Result: {'PASS' if passed else 'FAIL'}")

print("\nG2_TRACES_4_5 =", "PASS" if all_pass else "FAIL")
