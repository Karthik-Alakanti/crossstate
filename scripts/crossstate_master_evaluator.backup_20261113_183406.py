#!/usr/bin/env python3
"""CrossState master evaluator: synthetic/real trace + simulation/live BMv2-XDP."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import struct
import sys
import time
import inspect

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ref.model import Ev, canon, slot_of
from scripts import crossstate_demo as demo


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")


def jwrite(path, obj):
    path.write_text(
        json.dumps(obj, indent=2, default=str) + "\n",
        encoding="utf-8"
    )


def readcsv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def writecsv(path, rows):
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def mkframe(src, dst, sp, dp, inside, flags, length, ts, pid):
    payload = bytes(
        ((pid + i * 17) & 255)
        for i in range(length - 40)
    )

    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, length, pid & 65535,
        0x4000, 64, 6, 0,
        src.to_bytes(4, "big"),
        dst.to_bytes(4, "big")
    )

    tcp = struct.pack(
        "!HHIIHHHH",
        sp, dp, pid * 1000, 0,
        (5 << 12) | (flags & 0x1ff),
        65535, 0, 0
    )

    shim = (
        ts.to_bytes(6, "big")
        + pid.to_bytes(4, "big")
        + bytes([1 if inside else 0])
        + b"\x08\x00"
    )

    ethernet = bytes.fromhex(
        "020000000001020000000002"
    ) + b"\x88\xb5"

    return ethernet + shim + ip + tcp + payload


def synthetic_dataset(outdir, packets, flows_wanted, seed):

    if packets < 6:
        raise ValueError(
            "Synthetic mode requires at least 6 packets."
        )

    if packets > 0xffffffff:
        raise ValueError(
            "Packet budget exceeds packet-id field capacity."
        )

    if flows_wanted is None:
        n = max(2, min(200, round(packets / 32)))
        n -= n % 2
    else:
        n = flows_wanted
        if n % 2:
            n -= 1
            print(
                f"NOTICE: using {n} flows for equal migration cohorts."
            )

    n = min(n, (packets // 3) // 2 * 2, 65536)

    if n < 2:
        raise ValueError(
            "Need at least two complete flows."
        )

    rng = random.Random(seed)

    counts = [packets // n] * n

    for i in range(packets % n):
        counts[i] += 1

    outdir.mkdir(parents=True, exist_ok=False)

    pcap = outdir / "mawi_crossstate_replay.pcap"
    manifest = outdir / "mawi_selected_flow_manifest.csv"

    rows = []
    used = set()
    pid = 1
    ts = 10_000_000

    with pcap.open("wb") as f:

        f.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2, 4, 0, 0, 65535, 1
            )
        )

        for fi, count in enumerate(counts):

            chosen = None

            for _ in range(100000):

                sip = (
                    0x0A400001
                    + rng.randrange(0x000EFFFF)
                )

                dip = 0xC6336401 + rng.randrange(0xFE)

                sp = 20000 + rng.randrange(40000)
                dp = 443 if fi % 3 else 8443

                key = tuple(
                    int(v)
                    for v in canon(
                        Ev(
                            sip, sp, dip, dp, 6,
                            True, True, False,
                            False, False, 40, ts
                        )
                    )
                )

                sl = int(slot_of(key))

                if sl not in used:
                    chosen = (sip, dip, sp, dp, key, sl)
                    used.add(sl)
                    break

            if chosen is None:
                raise RuntimeError(
                    "Could not allocate unique state slots. "
                    "Reduce --flows."
                )

            sip, dip, sp, dp, key, sl = chosen
            total_bytes = 0

            for k in range(count):

                if k == 0:
                    inside, flags = True, 0x02
                elif k == 1:
                    inside, flags = False, 0x12
                elif k == 2:
                    inside, flags = True, 0x10
                else:
                    inside, flags = (k % 2 == 0), 0x10

                if inside:
                    src, dst, sport, dport = sip, dip, sp, dp
                else:
                    src, dst, sport, dport = dip, sip, dp, sp

                length = (
                    40 if k < 3
                    else 64 + ((fi * 13 + k * 29) % 1160)
                )

                frame = mkframe(
                    src, dst, sport, dport,
                    inside, flags, length, ts, pid
                )

                sec, usec = divmod(ts, 1_000_000)

                f.write(
                    struct.pack(
                        "<IIII",
                        sec, usec, len(frame), len(frame)
                    )
                )
                f.write(frame)

                total_bytes += length
                pid += 1
                ts += 1000

            rows.append({
                "index": fi,
                "slot": sl,
                "key": key,
                "packets": count,
                "ip_bytes": total_bytes
            })

    with manifest.open("w", newline="", encoding="utf-8") as f:

        w = csv.DictWriter(
            f,
            fieldnames=[
                "index", "slot", "key",
                "packets", "ip_bytes"
            ]
        )

        w.writeheader()

        for r in rows:
            w.writerow({
                **r,
                "key": json.dumps(list(r["key"]))
            })

    jwrite(
        outdir / "mawi_dataset_summary.json",
        {
            "dataset": "Generated synthetic CrossState TCP workload",
            "dataset_type": "synthetic",
            "seed": seed,
            "requested_packets": packets,
            "generated_packets": packets,
            "generated_flows": n,
            "packet_count_is_exact": True,
            "note": "Synthetic packets, not observed network traffic."
        }
    )

    parsed = demo.read_manifest(manifest)
    loaded = demo.load_replay(pcap, parsed)

    if sum(map(len, loaded.values())) != packets:
        raise RuntimeError(
            "Synthetic PCAP did not validate to exact packet count."
        )

    return parsed, loaded, packets


def choose_real(rows, flows, budget, cap, require_even):

    chosen = []
    used = 0

    for r in rows:

        if cap is not None and len(chosen) >= cap:
            break

        count = len(flows.get(int(r["index"]), []))

        if count and used + count <= budget:
            chosen.append(r)
            used += count

    if require_even and len(chosen) % 2:
        chosen.pop()

    if len(chosen) < 2:
        raise ValueError(
            "Budget selected fewer than two complete flows. "
            "Increase --packets."
        )

    slots = [int(r["slot"]) for r in chosen]

    if len(slots) != len(set(slots)):
        raise ValueError(
            "Selected trace contains state-slot collisions."
        )

    return chosen, used


def class_metrics(rows):

    use = [
        r for r in rows
        if str(r.get("expected", "")).upper()
        in ("ALLOW", "DROP")
        and str(r.get("observed", "")).upper()
        in ("ALLOW", "DROP")
    ]

    tp = sum(
        r["expected"].upper() == "ALLOW"
        and r["observed"].upper() == "ALLOW"
        for r in use
    )

    tn = sum(
        r["expected"].upper() == "DROP"
        and r["observed"].upper() == "DROP"
        for r in use
    )

    fp = sum(
        r["expected"].upper() == "DROP"
        and r["observed"].upper() == "ALLOW"
        for r in use
    )

    fn = sum(
        r["expected"].upper() == "ALLOW"
        and r["observed"].upper() == "DROP"
        for r in use
    )

    div = math.sqrt(
        (tp + fp) * (tp + fn)
        * (tn + fp) * (tn + fn)
    )

    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    spec = tn / (tn + fp) if tn + fp else None

    f1 = (
        2 * prec * rec / (prec + rec)
        if prec is not None and rec is not None
        and prec + rec
        else None
    )

    return {
        "count": len(use),
        "TP_allow": tp,
        "TN_drop": tn,
        "FP_false_allow": fp,
        "FN_false_drop": fn,
        "accuracy_percent": (
            100 * (tp + tn) / len(use) if use else None
        ),
        "precision_percent": (
            100 * prec if prec is not None else None
        ),
        "recall_percent": (
            100 * rec if rec is not None else None
        ),
        "specificity_percent": (
            100 * spec if spec is not None else None
        ),
        "F1_percent": (
            100 * f1 if f1 is not None else None
        ),
        "false_allow_rate_percent": (
            100 * fp / (tn + fp) if tn + fp else None
        ),
        "false_drop_rate_percent": (
            100 * fn / (tp + fn) if tp + fn else None
        ),
        "MCC": (
            (tp * tn - fp * fn) / div if div else None
        ),
        "class_support_allow": tp + fn,
        "class_support_drop": tn + fp
    }


def collect_decisions(simdir, livedir, controldir):

    res = {}

    if simdir:

        rows = readcsv(
            simdir / "simulation_packet_decisions.csv"
        )

        for t in ("bmv2", "xdp"):

            rr = [
                r for r in rows
                if r.get("kind")
                in ("mawi_replay", "dataset_replay")
                and r.get("target", "").replace("-sim", "") == t
            ]

            cc = [
                r for r in rows
                if r.get("kind") == "synthetic_control"
            ]

            res[f"simulation_{t}_trace"] = class_metrics(rr)
            res[f"simulation_{t}_controls"] = class_metrics(cc)

    if livedir:

        rows = readcsv(livedir / "packet_decisions.csv")

        for t in ("bmv2", "xdp"):
            res[f"live_{t}_trace"] = class_metrics([
                r for r in rows
                if r.get("target", "").lower() == t
            ])

    if controldir:

        rows = readcsv(
            controldir / "live_control_decisions.csv"
        )

        for t in ("bmv2", "xdp"):
            res[f"live_{t}_controls"] = class_metrics([
                r for r in rows
                if r.get("target", "").lower() == t
            ])

    return res


def collect_state(livedir, simsummary):

    if livedir:

        b = livedir / "04_final_bmv2.json"
        x = livedir / "04_final_xdp.json"

        if b.exists() and x.exists():

            B = {
                int(r["slot"]): r
                for r in json.loads(b.read_text()).get("records", [])
            }

            X = {
                int(r["slot"]): r
                for r in json.loads(x.read_text()).get("records", [])
            }

            union = set(B) | set(X)
            common = set(B) & set(X)

            fields = ("key", "st", "last", "pkts", "bytes")

            exact = sum(
                tuple(B[s].get(k) for k in fields)
                == tuple(X[s].get(k) for k in fields)
                for s in common
            )

            return {
                "bmv2_records": len(B),
                "xdp_records": len(X),
                "union_slots": len(union),
                "common_slots": len(common),
                "exact_matches": exact,
                "divergent_slots": len(union) - exact,
                "exact_record_agreement_percent": (
                    100 * exact / len(union) if union else 100.0
                ),
                "packet_counter_parity_percent": (
                    100 * sum(
                        B[s].get("pkts") == X[s].get("pkts")
                        for s in common
                    ) / len(common) if common else 100.0
                ),
                "byte_counter_parity_percent": (
                    100 * sum(
                        B[s].get("bytes") == X[s].get("bytes")
                        for s in common
                    ) / len(common) if common else 100.0
                )
            }

    if simsummary:

        return {
            "source": "in-memory reference simulation",
            "final_exact_state_equivalence":
                simsummary.get("final_exact_state_equivalence"),
            "bmv2_records":
                simsummary.get("final_bmv2_sim_records"),
            "xdp_records":
                simsummary.get("final_xdp_sim_records"),
            "scope": (
                "Both simulation tables use the Python reference "
                "model; not independent target validation."
            )
        }

    return {"status": "not_run"}


def main():

    ap = argparse.ArgumentParser(
        description=__doc__
    )

    ap.add_argument(
        "--dataset",
        choices=["synthetic", "real"],
        default="real"
    )

    ap.add_argument(
        "--backend",
        choices=["simulate", "live", "both"],
        default="simulate"
    )

    ap.add_argument("--packets", type=int, default=5000)
    ap.add_argument("--flows", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)

    ap.add_argument(
        "--run-dir",
        type=Path,
        default=demo.DEFAULT_RUN
    )

    ap.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts/evaluations"
    )

    ap.add_argument("--batch-size", type=int, default=40)
    ap.add_argument("--inter-packet-ms", type=float, default=0.2)

    args = ap.parse_args()

    if args.packets < 1:
        ap.error("--packets must be positive")

    if args.flows is not None and args.flows < 2:
        ap.error("--flows must be at least 2")

    outroot = args.output_dir.expanduser().resolve()
    outroot.mkdir(parents=True, exist_ok=True)

    out = outroot / f"evaluation_{stamp()}"
    out.mkdir()

    prepared = out / "prepared_dataset"

    if args.dataset == "synthetic":

        rows, flows, available = synthetic_dataset(
            prepared,
            args.packets,
            args.flows,
            args.seed
        )

        selected = args.packets

        source = json.loads(
            (prepared / "mawi_dataset_summary.json").read_text()
        )

    else:

        src = args.run_dir.expanduser().resolve()

        for name in (
            "mawi_selected_flow_manifest.csv",
            "mawi_crossstate_replay.pcap",
            "mawi_dataset_summary.json"
        ):
            if not (src / name).is_file():
                raise FileNotFoundError(src / name)

        allrows = demo.read_manifest(
            src / "mawi_selected_flow_manifest.csv"
        )

        allflows = demo.load_replay(
            src / "mawi_crossstate_replay.pcap",
            allrows
        )

        available = sum(len(v) for v in allflows.values())
        budget = min(args.packets, available)

        if args.packets > available:
            print(
                f"NOTICE: packet budget capped at dataset limit "
                f"{available:,}."
            )

        rows, selected = choose_real(
            allrows,
            allflows,
            budget,
            args.flows,
            args.backend in ("live", "both")
        )

        copied = demo.write_subset(
            src, rows, prepared
        )

        if copied != (len(rows), selected):
            raise RuntimeError(
                "Real trace subset verification failed."
            )

        flows = demo.load_replay(
            prepared / "mawi_crossstate_replay.pcap",
            rows
        )

        source = json.loads(
            (src / "mawi_dataset_summary.json").read_text()
        )

    rows = demo.read_manifest(
        prepared / "mawi_selected_flow_manifest.csv"
    )

    check = demo.load_replay(
        prepared / "mawi_crossstate_replay.pcap",
        rows
    )

    if sum(map(len, check.values())) != selected:
        raise RuntimeError(
            "Prepared trace failed final validation."
        )

    simsum = None
    simdir = None
    livesum = None
    livedir = None
    controls = None
    controldir = None

    if args.backend in ("simulate", "both"):

        t = time.perf_counter()

        simsum = demo.run_simulation(
            rows, check, out
        )

        simdir = out / "simulation"

        simsum["master_simulation_wall_seconds"] = (
            time.perf_counter() - t
        )

    if args.backend in ("live", "both"):

        sig = inspect.signature(demo.run_live)

        if "latency_samples" in sig.parameters:

            livesum = demo.run_live(
                prepared,
                rows,
                out,
                args.batch_size,
                args.inter_packet_ms,
                50
            )

        else:

            livesum = demo.run_live(
                prepared,
                rows,
                out,
                args.batch_size,
                args.inter_packet_ms
            )

        livedir = Path(
            livesum["output_directory"]
        ).expanduser().resolve()

        controls = demo.run_live_negative_controls(
            livedir,
            out,
            args.batch_size,
            args.inter_packet_ms
        )

        controldir = out / "live_controls"

    decisions = collect_decisions(
        simdir, livedir, controldir
    )

    state = collect_state(
        livedir, simsum
    )

    checkpoints = []
    migration = {}

    if livedir:

        for r in readcsv(
            livedir / "checkpoint_metrics.csv"
        ):

            try:
                checkpoints.append({
                    "checkpoint": r.get("checkpoint"),
                    "direction": r.get("direction"),
                    "duration_seconds": float(
                        r.get("duration_seconds") or 0
                    ),
                    "status": r.get("status")
                })
            except ValueError:
                pass

        vals = [
            r["duration_seconds"]
            for r in checkpoints
        ]

        migration = {
            "checkpoint_count": len(vals),
            "total_checkpoint_seconds": sum(vals),
            "mean_checkpoint_seconds": (
                sum(vals) / len(vals) if vals else None
            ),
            "checkpoint_p95_seconds": (
                sorted(vals)[
                    max(0, math.ceil(.95 * len(vals)) - 1)
                ] if vals else None
            ),
            "per_checkpoint": checkpoints,
            "traffic_pause_duration_seconds": None,
            "traffic_pause_note": (
                "Not directly measured; quiesced checkpoint "
                "wall time is not packet pause time."
            )
        }

    elif simdir:

        cps = readcsv(
            simdir / "simulation_checkpoint_metrics.csv"
        )

        vals = [
            float(r.get("in_memory_copy_seconds") or 0)
            for r in cps
        ]

        migration = {
            "checkpoint_count": len(cps),
            "total_in_memory_copy_seconds": sum(vals),
            "per_checkpoint": cps,
            "scope": (
                "In-memory dictionary copy only; "
                "not actual migration efficiency."
            )
        }

    perf = {}

    if (
        livedir
        and (livedir / "mawi_live_migration_summary.json").exists()
    ):
        perf = json.loads(
            (livedir / "mawi_live_migration_summary.json").read_text()
        )

    metrics = {
        "metadata": {
            "dataset": args.dataset,
            "source_label": source.get("dataset", args.dataset),
            "backend": args.backend,
            "requested_packets": args.packets,
            "available_packets": available,
            "selected_packets": selected,
            "selected_flows": len(rows),
            "packet_count_semantics": (
                "exact" if args.dataset == "synthetic"
                else "upper bound; complete flows only"
            ),
            "seed": args.seed if args.dataset == "synthetic" else None,
            "output_dir": str(out)
        },
        "decision_metrics": decisions,
        "state_metrics": state,
        "migration_metrics": migration,
        "live_performance": perf,
        "simulation_summary": simsum,
        "live_summary": livesum,
        "live_controls": controls
    }

    jwrite(out / "master_metrics.json", metrics)

    flat = []

    for name, m in decisions.items():
        for k, v in m.items():
            flat.append({
                "scope": name,
                "metric": k,
                "value": v
            })

    for group, d in (
        ("state", state),
        ("migration", migration),
        ("performance", perf)
    ):
        for k, v in d.items():
            if isinstance(v, (int, float, str)) or v is None:
                flat.append({
                    "scope": group,
                    "metric": k,
                    "value": v
                })

    writecsv(out / "metrics_summary.csv", flat)

    writecsv(
        out / "checkpoint_metrics_master.csv",
        checkpoints
    )

    # Publication-quality plots.
    try:

        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        pdir = out / "plots"
        pdir.mkdir()

        fig, ax = plt.subplots(figsize=(7, 4))

        ax.hist(
            [int(r["packets"]) for r in rows],
            bins=min(30, max(5, len(rows)))
        )

        ax.set(
            xlabel="Packets per flow",
            ylabel="Flow count",
            title="Selected workload packet distribution"
        )

        fig.tight_layout()

        for ext in ("png", "pdf", "svg"):
            fig.savefig(
                pdir / f"01_flow_packet_distribution.{ext}",
                dpi=300
            )

        plt.close(fig)

        names = [
            n for n in decisions
            if n.endswith("_controls")
        ]

        if names:

            fig, axes = plt.subplots(
                1, len(names),
                figsize=(5 * len(names), 4)
            )

            axes = [axes] if len(names) == 1 else list(axes)

            for ax, name in zip(axes, names):

                m = decisions[name]

                mat = [
                    [
                        m.get("TN_drop", 0),
                        m.get("FP_false_allow", 0)
                    ],
                    [
                        m.get("FN_false_drop", 0),
                        m.get("TP_allow", 0)
                    ]
                ]

                ax.imshow(mat)

                ax.set(
                    xticks=[0, 1],
                    xticklabels=["DROP", "ALLOW"],
                    yticks=[0, 1],
                    yticklabels=["DROP", "ALLOW"],
                    xlabel="Observed",
                    ylabel="Expected",
                    title=name
                )

                for i in range(2):
                    for j in range(2):
                        ax.text(
                            j, i, str(mat[i][j]),
                            ha="center", va="center"
                        )

            fig.tight_layout()

            for ext in ("png", "pdf", "svg"):
                fig.savefig(
                    pdir / f"02_confusion_matrices.{ext}",
                    dpi=300
                )

            plt.close(fig)

        if checkpoints:

            fig, ax = plt.subplots(figsize=(7, 4))

            ax.bar(
                [f"CP{x['checkpoint']}" for x in checkpoints],
                [x["duration_seconds"] for x in checkpoints]
            )

            ax.set(
                ylabel="Seconds",
                title="Live checkpoint duration"
            )

            fig.tight_layout()

            for ext in ("png", "pdf", "svg"):
                fig.savefig(
                    pdir / f"03_checkpoint_duration.{ext}",
                    dpi=300
                )

            plt.close(fig)

    except ImportError:

        print(
            "matplotlib not installed: skipped plots; "
            "JSON/CSV reports were written."
        )

    report = f"""# CrossState Master Evaluation

- Dataset: {args.dataset} ({source.get('dataset', args.dataset)})
- Backend: {args.backend}
- Requested packets: {args.packets:,}
- Available packets: {available:,}
- Selected packets: {selected:,}
- Selected complete flows: {len(rows):,}
- Selection: {
    'exact synthetic count'
    if args.dataset == 'synthetic'
    else 'whole-flow upper bound, capped at dataset size'
}

## Correctness

{json.dumps(decisions, indent=2)}

## State

{json.dumps(state, indent=2)}

## Migration

{json.dumps(migration, indent=2)}

## Scope limits

Simulation is reference-model orchestration, not independent
datapath execution. Live throughput and latency are only reported
when the live runner instruments them. Traffic pause, NIC line-rate
throughput, one-way NIC latency, reordering, jitter, migration wire
bytes, and cryptographic migration security are not inferred
when unmeasured.
"""

    (out / "EVALUATION_REPORT.md").write_text(
        report, encoding="utf-8"
    )

    print(
        f"\nCROSSSTATE MASTER EVALUATION COMPLETE"
        f"\nPackets: {selected:,}; flows: {len(rows):,}"
        f"\nResults: {out}",
        flush=True
    )

    return 0


if __name__ == "__main__":

    try:
        raise SystemExit(main())

    except KeyboardInterrupt:
        raise SystemExit(130)

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"FAILED: {e}", file=sys.stderr)
        raise SystemExit(1)
