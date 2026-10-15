#!/usr/bin/env python3
"""Generate a deterministic, machine-readable CrossState v1 contract."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml

from ref import model
from scripts.validate_spec import validate_spec


FIELD_LAYOUT = {
    "ip_a": {
        "type": "ipv4",
        "bits": 32,
        "bytes": 4,
        "encoding": "big-endian",
    },
    "port_a": {
        "type": "u16",
        "bits": 16,
        "bytes": 2,
        "encoding": "big-endian",
    },
    "ip_b": {
        "type": "ipv4",
        "bits": 32,
        "bytes": 4,
        "encoding": "big-endian",
    },
    "port_b": {
        "type": "u16",
        "bits": 16,
        "bytes": 2,
        "encoding": "big-endian",
    },
    "proto": {
        "type": "u8",
        "bits": 8,
        "bytes": 1,
        "encoding": "single-byte",
    },
}

STATE_CODES = {
    "NEW": model.NEW,
    "EST": model.EST,
    "CLOSED": model.CLOSED,
}


def build_contract(spec):
    errors = validate_spec(spec)
    if errors:
        raise ValueError("Invalid specification:\n- " + "\n- ".join(errors))

    key_fields = [
        {"name": name, **FIELD_LAYOUT[name]}
        for name in spec["key"]
    ]
    key_bytes = sum(field["bytes"] for field in key_fields)

    if key_bytes != 13:
        raise ValueError(
            f"Expected a 13-byte flow key, computed {key_bytes} bytes."
        )

    value = spec["value"]

    return {
        "format": "crossstate-runtime-contract",
        "format_version": 1,
        "source_spec": "spec/firewall.yaml",
        "spec": {
            "name": spec["name"],
            "version": spec["version"],
            "table": {
                "slots": spec["slots"],
                "buckets": spec["buckets"],
                "hash": spec["hash"],
                "clock": spec["clock"],
                "idle_timeout_us": spec["idle_timeout_us"],
                "collision": spec["collision"],
                "expiry": spec["expiry"],
            },
            "key_fields": key_fields,
            "value": value,
        },
        "runtime_contract": {
            "semantics_source": "ref/model.py",
            "flow_key": {
                "canonicalization": (
                    "Sort endpoints by (IPv4 address << 16) | port"
                ),
                "serialized_length_bytes": key_bytes,
                "field_encoding": "network byte order",
            },
            "hash": {
                "algorithm": "CRC-32",
                "input_bytes": key_bytes,
                "slot_expression": "crc32(key_bytes) % slots",
            },
            "state_codes": STATE_CODES,
            "timeout": {
                "unit": "us",
                "live_when_elapsed_le_timeout": True,
                "expired_flow_behavior": (
                    "Allow and replace on inside SYN without ACK; "
                    "otherwise drop"
                ),
                "expiry_policy": spec["expiry"],
            },
            "counters": {
                "width_bits": 64,
                "overflow": "wrap modulo 2^64",
                "fields": ["pkts", "bytes"],
            },
        },
    }


def serialize_contract(contract):
    """Stable serialization: no timestamps or machine-specific paths."""
    return json.dumps(
        contract,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts/generated/firewall_contract.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check that the existing generated file is current.",
    )
    args = parser.parse_args()

    spec_path = ROOT / "spec/firewall.yaml"

    try:
        with spec_path.open(encoding="utf-8") as f:
            spec = yaml.safe_load(f)

        contract = build_contract(spec)
        generated = serialize_contract(contract)
    except Exception as exc:
        print(f"CONTRACT_GENERATION = FAIL\n{exc}", file=sys.stderr)
        return 1

    output = args.output
    if not output.is_absolute():
        output = ROOT / output

    if args.check:
        if not output.is_file():
            print(f"Generated contract missing: {output}", file=sys.stderr)
            return 1

        existing = output.read_text(encoding="utf-8")
        if existing != generated:
            print("Generated contract is stale; regenerate it.", file=sys.stderr)
            return 1

        print(f"Contract is up to date: {output.relative_to(ROOT)}")
        print("CONTRACT_GENERATION = PASS")
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(generated, encoding="utf-8")

    print(f"Generated: {output.relative_to(ROOT)}")
    print(f"Key length: {contract['runtime_contract']['flow_key']['serialized_length_bytes']} bytes")
    print(f"Table slots: {spec['slots']}")
    print(f"States: {len(contract['runtime_contract']['state_codes'])}")
    print("CONTRACT_GENERATION = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
