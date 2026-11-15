import ipaddress
import json
import random
import struct
import subprocess
import time

from scapy.all import AsyncSniffer, Ether, IP, TCP, Raw, get_if_hwaddr, sendp
from ref.model import Ev, canon, key_bytes, slot_of

TX_IFACE = "cs-xdp-host"
RX_IFACE = "cs-xdp"
BASE_TS = 100_000_000
BASE_ID = 1000
NUM_TESTS = 20

# Previously tested live slot and its canonical key.
EXISTING_SLOT = 30468
EXISTING_KEY = (577090037, 37303, 3639700191, 52577, 6)

def canonical_key(values):
    ia, pa, ib, pb, proto = values
    return canon(Ev(
        int(ia), int(pa), int(ib), int(pb), int(proto),
        True, True, False, False, False, 40, 0,
    ))

def run_json(args):
    return json.loads(subprocess.check_output(args, text=True))

def decode_bytes(value):
    # bpftool JSON may represent bytes as integers or hex strings.
    if isinstance(value, list):
        if all(isinstance(v, int) for v in value):
            return bytes(value)
        if all(isinstance(v, str) for v in value):
            return bytes(int(v, 16) for v in value)
    if isinstance(value, str):
        return bytes.fromhex(value.replace(" ", ""))
    raise ValueError(f"Unsupported bpftool byte representation: {type(value).__name__}")

# Find the actual map used by the loaded program.
maps = run_json(["bpftool", "-j", "map", "show"])
flow_maps = [m for m in maps if m.get("name") == "flow_state"]
if not flow_maps:
    raise SystemExit("FAIL: flow_state map not found. Is XDP attached?")
map_id = flow_maps[0]["id"]

# Derive canonical test cases from the existing vector file.
with open("artifacts/crc_vectors.json") as f:
    vectors = json.load(f)

rng = random.Random(20261015)
cases = []
seen_slots = {}
seen_keys = set()

def try_add(raw_key, origin):
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
    cases.append((key, slot, origin))
    return True

for row in vectors:
    try_add(row["key"], "existing-vector")

# Ensure 20 distinct slots, avoiding collisions with existing state.
while len(cases) < NUM_TESTS:
    ip_a = rng.getrandbits(32)
    ip_b = rng.getrandbits(32)
    port_a = rng.getrandbits(16)
    port_b = rng.getrandbits(16)

    if (ip_a, port_a) == (ip_b, port_b):
        continue

    try_add((ip_a, port_a, ip_b, port_b, 6), "supplemental")

# Reset these array-map slots so reruns begin from a clean state.
print(f"Resetting {len(cases)} XDP test slots...")
zero_value = ["00"] * 40

for _, slot, _ in cases:
    slot_bytes = struct.pack("<I", slot)
    subprocess.run(
        [
            "bpftool", "map", "update", "id", str(map_id),
            "key", "hex",
            *[f"{b:02x}" for b in slot_bytes],
            "value", "hex", *zero_value,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )

print("Test slots reset.")

# Build and transmit synthetic packets.
host_mac = get_if_hwaddr(TX_IFACE)
xdp_mac = get_if_hwaddr(RX_IFACE)
test_packets = {}

sniffer = AsyncSniffer(iface=RX_IFACE, store=True)
sniffer.start()
time.sleep(0.3)

for i, (key, slot, origin) in enumerate(cases):
    ia, pa, ib, pb, proto = key
    ts = BASE_TS + i
    pkt_id = BASE_ID + i

    shim = (
        ts.to_bytes(6, "big")
        + pkt_id.to_bytes(4, "big")
        + b"\x01"
        + b"\x08\x00"
    )

    packet = (
        Ether(src=host_mac, dst=xdp_mac, type=0x88B5)
        / Raw(shim)
        / IP(
            src=str(ipaddress.IPv4Address(ia)),
            dst=str(ipaddress.IPv4Address(ib)),
        )
        / TCP(sport=pa, dport=pb, flags="S", seq=1)
    )

    test_packets[pkt_id] = (key, slot, ts)
    sendp(packet, iface=TX_IFACE, verbose=False)
    time.sleep(0.025)

time.sleep(0.5)
captured = sniffer.stop()

# Collect the XDP-modified flags from the receiving peer.
observed_flags = {}
for packet in captured:
    raw = bytes(packet)
    if len(raw) < 27 or raw[12:14] != b"\x88\xb5":
        continue

    pkt_id = int.from_bytes(raw[20:24], "big")
    if pkt_id in test_packets:
        observed_flags.setdefault(pkt_id, []).append(raw[24])

# Compare each packet decision and its state-map key against Python.
print("========== XDP RUNTIME CRC / SLOT TEST ==========")
passed = 0

for i, (key, slot, origin) in enumerate(cases):
    ts = BASE_TS + i
    pkt_id = BASE_ID + i
    flags = observed_flags.get(pkt_id, [])

    try:
        # BPF array-map keys are native-endian u32.
        key_bytes_le = struct.pack("<I", slot)
        lookup = run_json([
            "bpftool", "-j", "map", "lookup",
            "id", str(map_id), "key", "hex",
            *[f"{b:02x}" for b in key_bytes_le],
        ])
        record = lookup.get("value", lookup)

        if isinstance(record, list):
            # bpftool JSON exposes the 40-byte C struct as raw bytes.
            raw = decode_bytes(record)
            if len(raw) != 40:
                raise ValueError(
                    f"Unexpected flow_record size: {len(raw)}"
                )

            stored_key = list(raw[0:13])
            state = raw[13]
            valid = raw[14]
            last = int.from_bytes(raw[16:24], "little")
            pkts = int.from_bytes(raw[24:32], "little")
            byte_count = int.from_bytes(raw[32:40], "little")

        elif isinstance(record, dict):
            # Support bpftool versions that decode BTF into fields.
            stored_key = record.get("key", [])
            state = record.get("st")
            valid = record.get("valid")
            last = record.get("last")
            pkts = record.get("pkts")
            byte_count = record.get("bytes")

        else:
            raise ValueError(
                f"Unexpected map value type: {type(record).__name__}"
            )

        map_ok = (
            stored_key == list(key_bytes(key))
            and valid == 1
            and state == 1
            and last == ts
            and pkts == 1
            and byte_count == 40
        )
    except (subprocess.CalledProcessError, KeyError, TypeError, ValueError):
        map_ok = False

    packet_ok = 0x05 in flags
    ok = packet_ok and map_ok
    passed += int(ok)

    print(
        f"{i+1:02d}. slot={slot:5d} "
        f"flags={[f'0x{x:02x}' for x in flags]} "
        f"packet={'PASS' if packet_ok else 'FAIL'} "
        f"record={'PASS' if map_ok else 'FAIL'} "
        f"overall={'PASS' if ok else 'FAIL'}"
    )

print(f"\nXDP_RUNTIME_CRC_RESULT = {passed}/{NUM_TESTS}")
print("G3A_RUNTIME_CRC =", "PASS" if passed == NUM_TESTS else "FAIL")
