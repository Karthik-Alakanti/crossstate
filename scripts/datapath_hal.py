#!/usr/bin/env python3
"""CrossState Datapath Hardware Abstraction Layer (HAL).

Defines a target-agnostic interface for reading and writing flow state,
supporting software targets (P4/BMv2 via Thrift CLI, eBPF/XDP via bpftool)
and hardware targets (P4 To
fino, eBPF SmartNIC) through the same logical operations.

Concrete backends:
  - Bmv2Target:    simple_switch_CLI register reads/writes (software)
  - XdpTarget:     bpftool map reads/writes (software)
  - TofinoTarget:  P4 Runtime gNMI/ptf (hardware - unavailable, stub)
  - SmartNicTarget: eBPF on SmartNIC via libbpf (hardware - unavailable, stub)

All backends implement the same DatapathTarget ABC so the migration,
failover, and checkpoint code is target-agnostic.

HardwareUnavailableError is raised by hardware backends when no physical
device is attached. Use is_available() to check before operating.
"""

from __future__ import annotations

import abc
import json
import subprocess
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ref.model import key_bytes, slot_of

SLOT_COUNT = 65536
RECORD_BYTES = 40
KEY_BYTES = 13
LOGICAL_FIELDS = ("st", "last", "pkts", "bytes")


class HardwareUnavailableError(RuntimeError):
    """Raised when a hardware target operation is attempted but no physical
    device is attached or wired. Use is_available() to check before operating."""
    pass


@dataclass
class DatapathRecord:
    """A single flow-state record in normalized logical form."""
    slot: int
    key: list[int]
    st: int
    last: int
    pkts: int
    bytes: int
    chain_index: int = 0
    synced: int = 0
    valid: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot": self.slot,
            "key": self.key,
            "st": self.st,
            "last": self.last,
            "pkts": self.pkts,
            "bytes": self.bytes,
            "chain_index": self.chain_index,
            "synced": self.synced,
            "valid": self.valid,
        }

    def matches(self, other: "DatapathRecord") -> bool:
        return (
            self.key == other.key
            and self.chain_index == other.chain_index
            and all(getattr(self, f) == getattr(other, f) for f in LOGICAL_FIELDS)
        )


@dataclass
class DatapathHealth:
    """Health status of a datapath target."""
    target: str
    reachable: bool
    last_check_utc: str
    latency_ms: float | None = None
    error: str | None = None
    consecutive_failures: int = 0


class DatapathTarget(abc.ABC):
    """Abstract target interface. Concrete backends implement read/write."""

    def __init__(self, name: str, target_type: str):
        self.name = name
        self.target_type = target_type
        self.consecutive_failures = 0
        self.last_health: DatapathHealth | None = None

    @abc.abstractmethod
    def export_all(self) -> list[DatapathRecord]:
        """Export all valid records from the datapath."""

    @abc.abstractmethod
    def read_slot(self, slot: int) -> DatapathRecord | None:
        """Read one slot; None if empty/invalid."""

    @abc.abstractmethod
    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        """Write one record; optionally verify read-back."""

    @abc.abstractmethod
    def clear_slot(self, slot: int) -> None:
        """Mark a slot invalid (logically empty)."""

    @abc.abstractmethod
    def health_check(self) -> DatapathHealth:
        """Return current health status."""

    @abc.abstractmethod
    def is_hardware(self) -> bool:
        """True if this is a hardware target (Tofino/SmartNIC)."""


# ---------------------------------------------------------------------------
# Software backends (available today)
# ---------------------------------------------------------------------------

class Bmv2Target(DatapathTarget):
    """P4/BMv2 via simple_switch_CLI Thrift interface."""

    def __init__(self, name: str = "bmv2", thrift_port: int = 9090):
        super().__init__(name, "P4/BMv2 (software)")
        self.thrift_port = thrift_port
        self._cli_cache: dict[str, str] = {}

    def _cli(self, commands: list[str]) -> str:
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
            input="\n".join(commands) + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"simple_switch_CLI exited {result.returncode}: {result.stderr[-1000:]}"
            )
        output = result.stdout + "\n" + result.stderr
        import re
        if re.search(
            r"(?im)^.*(?:Error:|Exception:|Invalid value|Cannot find register).*$",
            output,
        ):
            raise RuntimeError(f"BMv2 CLI error: {output[-2000:]}")
        return output

    def _parse_indexed(self, output: str, requests: list[tuple[str, int]]) -> dict[tuple[str, int], int]:
        import re
        parsed = {}
        for name, slot in requests:
            pattern = rf"(?:RuntimeCmd:\s*)?{re.escape(name)}\s*\[\s*{slot}\s*\]\s*=\s*(\d+)"
            matches = re.findall(pattern, output)
            if len(matches) != 1:
                raise ValueError(f"Expected one result for {name}[{slot}], found {len(matches)}.")
            parsed[(name, slot)] = int(matches[0])
        return parsed

    def export_all(self) -> list[DatapathRecord]:
        # Read valid bitmap first
        output = self._cli(["register_read r_valid"])
        import re
        pattern = r"r_valid\s*=\s*(.*?)(?=\nRuntimeCmd:|\Z)"
        match = re.search(pattern, output, flags=re.DOTALL)
        if not match:
            raise RuntimeError("Could not read r_valid bitmap.")
        valid = [int(t.strip()) for t in match.group(1).strip().split(",")]
        slots = [s for s, f in enumerate(valid) if f == 1]
        return self._read_slots(slots)

    def _read_slots(self, slots: list[int]) -> list[DatapathRecord]:
        if not slots:
            return []
        names = ["r_valid", "r_ipa", "r_pa", "r_ipb", "r_pb", "r_st",
                 "r_last", "r_pkts", "r_bytes", "r_synced"]
        requests = [(n, s) for s in slots for n in names]
        commands = [f"register_read {n} {s}" for n, s in requests]
        output = self._cli(commands)
        values = self._parse_indexed(output, requests)
        records = []
        for slot in slots:
            fields = {n: values[(n, slot)] for n in names}
            if fields["r_valid"] != 1:
                continue
            records.append(DatapathRecord(
                slot=slot,
                key=[fields["r_ipa"], fields["r_pa"], fields["r_ipb"], fields["r_pb"], 6],
                st=fields["r_st"],
                last=fields["r_last"],
                pkts=fields["r_pkts"],
                bytes=fields["r_bytes"],
                chain_index=0,
                synced=fields["r_synced"],
            ))
        return records

    def read_slot(self, slot: int) -> DatapathRecord | None:
        recs = self._read_slots([slot])
        return recs[0] if recs else None

    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        import re
        slot = record.slot
        commands = [
            f"register_write r_valid {slot} 0",
            f"register_write r_ipa {slot} {record.key[0]}",
            f"register_write r_pa {slot} {record.key[1]}",
            f"register_write r_ipb {slot} {record.key[2]}",
            f"register_write r_pb {slot} {record.key[3]}",
            f"register_write r_st {slot} {record.st}",
            f"register_write r_last {slot} {record.last}",
            f"register_write r_pkts {slot} {record.pkts}",
            f"register_write r_bytes {slot} {record.bytes}",
            f"register_write r_synced {slot} {record.synced}",
            f"register_write r_valid {slot} 1",
        ]
        self._cli(commands)
        if verify:
            actual = self.read_slot(slot)
            if actual is None or not actual.matches(record):
                raise RuntimeError(f"BMv2 post-write verification failed at slot {slot}.")

    def clear_slot(self, slot: int) -> None:
        self._cli([f"register_write r_valid {slot} 0"])

    def health_check(self) -> DatapathHealth:
        t0 = datetime.now(timezone.utc)
        try:
            self._cli(["register_read r_valid 0"])
            latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0
            self.consecutive_failures = 0
            health = DatapathHealth(
                target=self.name,
                reachable=True,
                last_check_utc=t0.isoformat(),
                latency_ms=latency,
                consecutive_failures=0,
            )
        except Exception as exc:
            self.consecutive_failures += 1
            health = DatapathHealth(
                target=self.name,
                reachable=False,
                last_check_utc=t0.isoformat(),
                error=str(exc),
                consecutive_failures=self.consecutive_failures,
            )
        self.last_health = health
        return health

    def is_hardware(self) -> bool:
        return False


class XdpTarget(DatapathTarget):
    """eBPF/XDP via bpftool map interface."""

    def __init__(self, name: str = "xdp", map_name: str = "flow_state"):
        super().__init__(name, "eBPF/XDP (software)")
        self.map_name = map_name
        self._map_id_cache: int | None = None

    def _run_json(self, args: list[str]) -> Any:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed: {' '.join(args)}\n{result.stderr.strip()}"
            )
        return json.loads(result.stdout)

    def _map_id(self) -> int:
        if self._map_id_cache is None:
            maps = self._run_json(["bpftool", "-j", "map", "show"])
            matches = [m for m in maps if m.get("name") == self.map_name]
            if len(matches) != 1:
                raise RuntimeError(f"Expected one {self.map_name} map, found {len(matches)}.")
            self._map_id_cache = matches[0]["id"]
        return self._map_id_cache

    def _encode(self, record: DatapathRecord) -> bytes:
        raw = bytearray(RECORD_BYTES)
        raw[0:13] = key_bytes(tuple(record.key))
        raw[13] = record.st
        raw[14] = record.valid
        raw[15] = 0
        raw[16:24] = record.last.to_bytes(8, "little")
        raw[24:32] = record.pkts.to_bytes(8, "little")
        raw[32:40] = record.bytes.to_bytes(8, "little")
        return bytes(raw)

    def _decode(self, slot: int, raw: bytes) -> DatapathRecord | None:
        if len(raw) != RECORD_BYTES:
            raise ValueError(f"Expected {RECORD_BYTES}-byte record, got {len(raw)}.")
        key = (
            int.from_bytes(raw[0:4], "big"),
            int.from_bytes(raw[4:6], "big"),
            int.from_bytes(raw[6:10], "big"),
            int.from_bytes(raw[10:12], "big"),
            raw[12],
        )
        state = raw[13]
        valid = raw[14]
        if valid not in (0, 1):
            raise ValueError(f"Unexpected valid flag: {valid}.")
        if valid == 0:
            return None
        return DatapathRecord(
            slot=slot,
            key=list(key),
            st=state,
            last=int.from_bytes(raw[16:24], "little"),
            pkts=int.from_bytes(raw[24:32], "little"),
            bytes=int.from_bytes(raw[32:40], "little"),
        )

    def _parse_bpftool_value(self, val: Any) -> bytes:
        """Parse a bpftool JSON value that may be dict, str, list of hex strings, or list of ints."""
        if isinstance(val, dict):
            return bytes.fromhex(val.get("value", "").replace(":", ""))
        if isinstance(val, str):
            return bytes.fromhex(val.replace(":", ""))
        if isinstance(val, list):
            return bytes(int(x, 16) if isinstance(x, str) else x for x in val)
        return bytes(val)

    def export_all(self) -> list[DatapathRecord]:
        map_id = self._map_id()
        dump = self._run_json(["bpftool", "-j", "map", "dump", "id", str(map_id)])
        entries = dump if isinstance(dump, list) else dump.get("entries", [])
        records = []
        for entry in entries:
            raw_map_key = self._parse_bpftool_value(entry["key"])
            slot = int.from_bytes(raw_map_key[:4], "little")
            raw_val = self._parse_bpftool_value(entry["value"])
            rec = self._decode(slot, raw_val)
            if rec is not None:
                records.append(rec)
        return records

    def read_slot(self, slot: int) -> DatapathRecord | None:
        map_id = self._map_id()
        key = struct.pack("<I", slot)
        result = self._run_json([
            "bpftool", "-j", "map", "lookup",
            "id", str(map_id), "key", "hex",
            *[f"{b:02x}" for b in key],
        ])
        raw = result["value"]
        raw = self._parse_bpftool_value(raw)
        return self._decode(slot, raw)

    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        map_id = self._map_id()
        key = struct.pack("<I", record.slot)
        raw = self._encode(record)
        args = [
            "bpftool", "map", "update",
            "id", str(map_id), "key", "hex",
            *[f"{b:02x}" for b in key],
            "value", "hex",
            *[f"{b:02x}" for b in raw],
            "any",
        ]
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"Map update failed at slot {record.slot}: {result.stderr.strip()}")
        if verify:
            actual = self.read_slot(record.slot)
            if actual is None or not actual.matches(record):
                raise RuntimeError(f"XDP post-write verification failed at slot {record.slot}.")

    def clear_slot(self, slot: int) -> None:
        map_id = self._map_id()
        key = struct.pack("<I", slot)
        zero = bytes(RECORD_BYTES)
        args = [
            "bpftool", "map", "update",
            "id", str(map_id), "key", "hex",
            *[f"{b:02x}" for b in key],
            "value", "hex",
            *[f"{b:02x}" for b in zero],
            "any",
        ]
        subprocess.run(args, capture_output=True, text=True, check=False)

    def health_check(self) -> DatapathHealth:
        t0 = datetime.now(timezone.utc)
        try:
            self._map_id()
            latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0
            self.consecutive_failures = 0
            health = DatapathHealth(
                target=self.name,
                reachable=True,
                last_check_utc=t0.isoformat(),
                latency_ms=latency,
                consecutive_failures=0,
            )
        except Exception as exc:
            self.consecutive_failures += 1
            health = DatapathHealth(
                target=self.name,
                reachable=False,
                last_check_utc=t0.isoformat(),
                error=str(exc),
                consecutive_failures=self.consecutive_failures,
            )
        self.last_health = health
        return health

    def is_hardware(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Hardware backends (stubs - hardware-gated; require physical hardware)
# ---------------------------------------------------------------------------

class TofinoTarget(DatapathTarget):
    """P4 Tofino via P4 Runtime / gNMI (hardware target - unavailable).

    This class provides the interface skeleton for P4/Tofino hardware targets.
    All data-plane operations raise HardwareUnavailableError because no physical
    Tofino device is attached. Use is_available() to check before operating.

    To wire to real hardware:
    1. Install p4runtime client library
    2. Connect to a Tofino device via gRPC
    3. Implement _ensure_client() with a Channel + WriteRequest stub
    4. Replace the HardwareUnavailableError raises with actual P4 Runtime calls
    """

    def __init__(self, name: str = "tofino", device_id: int = 0,
                 grpc_addr: str = "localhost:9559"):
        super().__init__(name, "P4/Tofino (hardware - unavailable)")
        self.device_id = device_id
        self.grpc_addr = grpc_addr
        self._client = None
        self._available = False

    def _ensure_client(self):
        raise HardwareUnavailableError(
            f"Tofino P4 Runtime client not available. "
            f"Device {self.device_id} at {self.grpc_addr} is not attached. "
            f"To use Tofino, install p4runtime, connect to a physical Tofino "
            f"device, and implement _ensure_client() with actual RPC calls."
        )

    def is_available(self) -> bool:
        """Return True only if a physical Tofino device is attached and wired."""
        return self._available and self._client is not None

    def is_hardware(self) -> bool:
        return True

    def export_all(self) -> list[DatapathRecord]:
        self._ensure_client()
        raise HardwareUnavailableError("Tofino export_all requires physical hardware.")

    def read_slot(self, slot: int) -> DatapathRecord | None:
        self._ensure_client()
        raise HardwareUnavailableError("Tofino read_slot requires physical hardware.")

    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        self._ensure_client()
        raise HardwareUnavailableError("Tofino write_record requires physical hardware.")

    def clear_slot(self, slot: int) -> None:
        self._ensure_client()
        raise HardwareUnavailableError("Tofino clear_slot requires physical hardware.")

    def health_check(self) -> DatapathHealth:
        t0 = datetime.now(timezone.utc)
        try:
            self._ensure_client()
            latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0
            self.consecutive_failures = 0
            return DatapathHealth(
                target=self.name, reachable=True,
                last_check_utc=t0.isoformat(),
                latency_ms=latency, consecutive_failures=0,
            )
        except HardwareUnavailableError:
            self.consecutive_failures += 1
            return DatapathHealth(
                target=self.name, reachable=False,
                last_check_utc=t0.isoformat(),
                error="Tofino hardware not available (no physical device attached)",
                consecutive_failures=self.consecutive_failures,
            )
        except Exception as exc:
            self.consecutive_failures += 1
            return DatapathHealth(
                target=self.name, reachable=False,
                last_check_utc=t0.isoformat(),
                error=str(exc), consecutive_failures=self.consecutive_failures,
            )


class SmartNicTarget(DatapathTarget):
    """eBPF SmartNIC via libbpf / netlink (hardware target - unavailable).

    This class provides the interface skeleton for eBPF/SmartNIC hardware
    targets. All data-plane operations raise HardwareUnavailableError because
    no physical SmartNIC device is attached. Use is_available() to check
    before operating.

    To wire to real hardware:
    1. Install libbpf development libraries
    2. Attach to a SmartNIC with eBPF offload support
    3. Implement _ensure_libbpf() with actual netlink/map operations
    4. Replace the HardwareUnavailableError raises with actual libbpf calls
    """

    def __init__(self, name: str = "smartnic", iface: str = "eth0",
                 map_name: str = "flow_state"):
        super().__init__(name, "eBPF/SmartNIC (hardware - unavailable)")
        self.iface = iface
        self.map_name = map_name
        self._available = False

    def _ensure_libbpf(self):
        raise HardwareUnavailableError(
            f"SmartNIC libbpf/netlink backend not available. "
            f"Interface {self.iface} has no SmartNIC attached. "
            f"To use SmartNIC, install libbpf, attach to a physical SmartNIC "
            f"with eBPF offload support, and implement _ensure_libbpf() with "
            f"actual netlink calls."
        )

    def is_available(self) -> bool:
        """Return True only if a physical SmartNIC is attached and wired."""
        return self._available

    def is_hardware(self) -> bool:
        return True

    def export_all(self) -> list[DatapathRecord]:
        self._ensure_libbpf()
        raise HardwareUnavailableError("SmartNIC export_all requires physical hardware.")

    def read_slot(self, slot: int) -> DatapathRecord | None:
        self._ensure_libbpf()
        raise HardwareUnavailableError("SmartNIC read_slot requires physical hardware.")

    def write_record(self, record: DatapathRecord, verify: bool = True) -> None:
        self._ensure_libbpf()
        raise HardwareUnavailableError("SmartNIC write_record requires physical hardware.")

    def clear_slot(self, slot: int) -> None:
        self._ensure_libbpf()
        raise HardwareUnavailableError("SmartNIC clear_slot requires physical hardware.")

    def health_check(self) -> DatapathHealth:
        t0 = datetime.now(timezone.utc)
        try:
            self._ensure_libbpf()
            latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000.0
            self.consecutive_failures = 0
            return DatapathHealth(
                target=self.name, reachable=True,
                last_check_utc=t0.isoformat(),
                latency_ms=latency, consecutive_failures=0,
            )
        except HardwareUnavailableError:
            self.consecutive_failures += 1
            return DatapathHealth(
                target=self.name, reachable=False,
                last_check_utc=t0.isoformat(),
                error="SmartNIC hardware not available (no physical device attached)",
                consecutive_failures=self.consecutive_failures,
            )
        except Exception as exc:
            self.consecutive_failures += 1
            return DatapathHealth(
                target=self.name, reachable=False,
                last_check_utc=t0.isoformat(),
                error=str(exc), consecutive_failures=self.consecutive_failures,
            )


# ---------------------------------------------------------------------------
# Target factory
# ---------------------------------------------------------------------------

def create_target(target_type: str, **kwargs) -> DatapathTarget:
    """Factory: create a DatapathTarget by type string.

    Only keyword arguments accepted by the target class are forwarded;
    unrelated kwargs (e.g. thrift_port for XdpTarget) are dropped.
    """
    types = {
        "bmv2": (Bmv2Target, {"name", "thrift_port"}),
        "xdp": (XdpTarget, {"name", "map_name"}),
        "tofino": (TofinoTarget, {"name", "device_id", "grpc_addr"}),
        "smartnic": (SmartNicTarget, {"name", "iface", "map_name"}),
    }
    if target_type not in types:
        raise ValueError(f"Unknown target type: {target_type}. "
                         f"Available: {list(types)}")
    cls, allowed_keys = types[target_type]
    filtered = {k: v for k, v in kwargs.items() if k in allowed_keys}
    return cls(**filtered)


if __name__ == "__main__":
    # Self-test: software backends instantiate without hardware.
    bmv2 = Bmv2Target(thrift_port=9090)
    xdp = XdpTarget()
    print(f"{bmv2.name}: {bmv2.target_type}, hardware={bmv2.is_hardware()}")
    print(f"{xdp.name}: {xdp.target_type}, hardware={xdp.is_hardware()}")
    tofino = TofinoTarget()
    smartnic = SmartNicTarget()
    print(f"{tofino.name}: {tofino.target_type}, hardware={tofino.is_hardware()}, available={tofino.is_available()}")
    print(f"{smartnic.name}: {smartnic.target_type}, hardware={smartnic.is_hardware()}, available={smartnic.is_available()}")
    h = tofino.health_check()
    print(f"Tofino health: reachable={h.reachable}, error={h.error}")
    h = smartnic.health_check()
    print(f"SmartNIC health: reachable={h.reachable}, error={h.error}")
    # Verify HardwareUnavailableError is raised on data-plane ops
    try:
        tofino.export_all()
    except HardwareUnavailableError as exc:
        print(f"Tofino export_all correctly raises HardwareUnavailableError: {exc}")
    try:
        smartnic.write_record(DatapathRecord(slot=0, key=[0,0,0,0,6], st=1, last=1000, pkts=1, bytes=40))
    except HardwareUnavailableError as exc:
        print(f"SmartNIC write_record correctly raises HardwareUnavailableError: {exc}")
