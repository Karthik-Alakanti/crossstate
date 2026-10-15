#!/usr/bin/env python3
"""Read XDP flow_state and export valid entries to a portable snapshot."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.state_snapshot import build_snapshot, serialize_snapshot

EXPECTED_VALUE_BYTES = 40
EXPECTED_KEY_BYTES = 13
DEFAULT_OUTPUT = ROOT / "artifacts/state/xdp_snapshot.json"


def run_json(args):
    result = subprocess.run(
        args,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(args)}\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Command returned invalid JSON: {' '.join(args)}"
        ) from exc


def parse_integer(value, field):
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            try:
                return int(value, 10)
            except ValueError:
                pass
    raise ValueError(f"{field} is not an integer: {value!r}")


def decode_bytes(value, field):
    """Decode bpftool's JSON representation of a byte array."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)

    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} is not a byte array.")

    decoded = []
    for index, item in enumerate(value):
        number = parse_integer(item, f"{field}[{index}]")
        if not 0 <= number <= 255:
            raise ValueError(f"{field}[{index}] is outside the byte range.")
        decoded.append(number)

    return bytes(decoded)


def decode_key(raw):
    if len(raw) != EXPECTED_KEY_BYTES:
        raise ValueError(
            f"Flow key must be {EXPECTED_KEY_BYTES} bytes, got {len(raw)}."
        )

    return (
        int.from_bytes(raw[0:4], "big"),
        int.from_bytes(raw[4:6], "big"),
        int.from_bytes(raw[6:10], "big"),
        int.from_bytes(raw[10:12], "big"),
        raw[12],
    )


def decode_record_value(value):
    """Return None for an invalid array slot or a normalized valid record."""
    if isinstance(value, (list, tuple)):
        raw = decode_bytes(value, "flow_record")

        if len(raw) != EXPECTED_VALUE_BYTES:
            raise ValueError(
                f"Expected {EXPECTED_VALUE_BYTES}-byte flow_record, "
                f"got {len(raw)}."
            )

        # C layout:
        # key[13] @ 0, st @ 13, valid @ 14, padding @ 15,
        # last @ 16, pkts @ 24, bytes @ 32.
        stored_key = decode_key(raw[0:13])
        state = raw[13]
        valid = raw[14]

        if valid not in (0, 1):
            raise ValueError(f"Unexpected valid flag: {valid}.")
        if valid == 0:
            return None

        return {
            "key": stored_key,
            "st": state,
            "last": int.from_bytes(raw[16:24], "little"),
            "pkts": int.from_bytes(raw[24:32], "little"),
            "bytes": int.from_bytes(raw[32:40], "little"),
        }

    # Some bpftool versions may expose BTF-decoded map values.
    if isinstance(value, dict):
        required = {"key", "st", "valid", "last", "pkts", "bytes"}
        missing = required - set(value)
        if missing:
            raise ValueError(
                f"BTF flow_record lacks fields: {sorted(missing)}."
            )

        valid = parse_integer(value["valid"], "valid")
        if valid not in (0, 1):
            raise ValueError(f"Unexpected valid flag: {valid}.")
        if valid == 0:
            return None

        raw_key = decode_bytes(value["key"], "flow_record.key")
        return {
            "key": decode_key(raw_key),
            "st": parse_integer(value["st"], "st"),
            "last": parse_integer(value["last"], "last"),
            "pkts": parse_integer(value["pkts"], "pkts"),
            "bytes": parse_integer(value["bytes"], "bytes"),
        }

    raise ValueError(
        f"Unsupported flow_record representation: {type(value).__name__}."
    )


def decode_map_entry(entry):
    if not isinstance(entry, dict) or "key" not in entry or "value" not in entry:
        raise ValueError("Unexpected bpftool map entry structure.")

    # BPF array-map keys are native-endian u32 values.
    raw_map_key = decode_bytes(entry["key"], "map key")
    if len(raw_map_key) != 4:
        raise ValueError(f"Expected 4-byte array-map key, got {len(raw_map_key)}.")

    slot = int.from_bytes(raw_map_key, "little")
    if not 0 <= slot < 65536:
        raise ValueError(f"Map slot outside range: {slot}.")

    decoded = decode_record_value(entry["value"])
    if decoded is None:
        return None

    return {
        "slot": slot,
        **decoded,
    }


def find_flow_state_map():
    maps = run_json(["bpftool", "-j", "map", "show"])
    if not isinstance(maps, list):
        raise RuntimeError("Unexpected bpftool map-show output.")

    matches = [item for item in maps if item.get("name") == "flow_state"]

    if not matches:
        raise RuntimeError(
            "flow_state map not found. Load and attach the CrossState XDP program."
        )

    if len(matches) != 1:
        identifiers = [item.get("id") for item in matches]
        raise RuntimeError(
            f"Multiple flow_state maps found: {identifiers}. "
            "Refusing to export an ambiguous map."
        )

    map_id = matches[0].get("id")
    if type(map_id) is not int:
        raise RuntimeError("bpftool did not return a numeric flow_state map ID.")

    return map_id


def export_records(map_dump):
    """Decode map-dump entries and return normalized valid records."""
    if isinstance(map_dump, dict):
        entries = map_dump.get("entries")
        if not isinstance(entries, list):
            raise ValueError("Unexpected map-dump JSON object.")
    elif isinstance(map_dump, list):
        entries = map_dump
    else:
        raise ValueError("Unexpected bpftool map-dump output.")

    records = []
    for index, entry in enumerate(entries):
        try:
            record = decode_map_entry(entry)
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Map entry {index}: {exc}") from exc

        if record is not None:
            records.append(record)

    return records, len(entries)


def main():
    parser = argparse.ArgumentParser(
        description="Export XDP flow_state into a CrossState v1 snapshot."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Snapshot JSON output path.",
    )
    args = parser.parse_args()

    try:
        map_id = find_flow_state_map()
        dump = run_json(["bpftool", "-j", "map", "dump", "id", str(map_id)])
        records, entries_read = export_records(dump)

        snapshot = build_snapshot("xdp", records)
        serialized = serialize_snapshot(snapshot)

        output = args.output
        if not output.is_absolute():
            output = ROOT / output

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialized, encoding="utf-8")

    except Exception as exc:
        print(f"XDP_STATE_EXPORT = FAIL\n{exc}", file=sys.stderr)
        return 1

    print("========== XDP STATE EXPORT ==========")
    print(f"Map ID: {map_id}")
    print(f"Map entries read: {entries_read}")
    print(f"Valid records exported: {len(records)}")
    print(f"Snapshot: {output}")
    print("XDP_STATE_EXPORT = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
