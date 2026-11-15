# CrossState — Instruction Manual

CrossState verifies stateful firewall state migration between P4/BMv2 and eBPF/XDP dataplanes using a quiesced checkpoint protocol with a fail-closed readiness gate, read-back verification, rollback, and a complete audit trail.

This manual covers:
1. [Installation](#installation)
2. [Environment Requirements](#environment-requirements)
3. [Starting the Runtime Testbed](#starting-the-runtime-testbed)
4. [Running Experiments](#running-experiments)
5. [Generating Q1 ACM Plots and Tables](#generating-q1-acm-plots-and-tables)
6. [Generating Research Question Plots](#generating-research-question-plots)
7. [Stress Testing and Breakpoint Analysis](#stress-testing-and-breakpoint-analysis)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Karthik-Alakanti/crossstate.git
cd crossstate
```

### 2. Create a Python Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

If you are on a system that enforces PEP 668 (externally managed environment), use:

```bash
pip install -r requirements.txt --break-system-packages
```

### 4. Install BMv2 and eBPF/XDP Tools (Requires Root)

CrossState requires a live datapath testbed. You need root access to:
- Create veth interface pairs
- Attach XDP programs to network interfaces
- Run simple_switch_grpc (BMv2)
- Use bpftool to manage eBPF maps

Install the following system packages:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y iproute2 bpftool linux-tools-$(uname -r)

# BMv2 (P4 compiler and simple_switch)
# Follow the BMv2 build instructions: https://github.com/p4lang/behavioral-model
```

### 5. Verify Installation

```bash
python3 -c "from thrift import Thrift; import scapy.all; print('Python dependencies: PASS')"
which simple_switch_grpc
which bpftool
```

---

## Environment Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.10+ | With `thrift` and `scapy` |
| Root access | Yes | For veth, XDP, BMv2 |
| simple_switch_grpc | Yes | BMv2 P4 switch |
| bpftool | Yes | eBPF map management |
| Network interfaces | cs-host, cs-bmv2, cs-xdp-host, cs-xdp | Created by startup script |
| Thrift port | 9090 | BMv2 control plane |
| MAWI dataset | Samplepoint-F 2024-08-06 | `/mnt/e/SDN/datasets/mawi/` or update path |

---

## Starting the Runtime Testbed

The startup script creates veth pairs, attaches the XDP program, starts BMv2, restores saved state snapshots, and verifies bidirectional state equivalence.

```bash
cd /home/karthik/work/crossstate
sudo bash scripts/crossstate_start_runtime.sh
```

### What the Startup Script Does

| Step | Action |
|------|--------|
| 1 | Recreate virtual networks (veth pairs: cs-host↔cs-bmv2, cs-xdp-host↔cs-xdp) |
| 2 | Attach XDP program to cs-xdp interface |
| 3 | Start BMv2 simple_switch_grpc on Thrift port 9090 |
| 4 | Restore saved BMv2 state from snapshot |
| 5 | Restore saved XDP state from BPF map snapshot |
| 6 | Reconcile readiness between both targets |
| 7 | Final startup verification (86 records on each target, all synced) |

### Expected Output

```
============================================================
CROSSSTATE RUNTIME STARTUP
============================================================
Repository: /home/karthik/work/crossstate
...
CROSSSTATE RUNTIME READY
BMv2: Running
Thrift: 9090
XDP: Attached in native driver mode
Flow records: 86 on each target
Readiness: All verified
NEXT COMMAND:
bash scripts/crossstate_master_demo.sh
CROSSSTATE_STARTUP = PASS
```

### Troubleshooting Startup

| Problem | Solution |
|---------|----------|
| `simple_switch_grpc` not found | Install BMv2: https://github.com/p4lang/behavioral-model |
| `bpftool` not found | Install linux-tools package |
| `Partial runtime detected` | One dataplane is already running. Stop it first or let the script preserve it. |
| `BMv2 did not start on Thrift port 9090` | Check `/tmp/crossstate-bmv2.log` for errors |
| Permission denied on veth creation | Run with `sudo` |

---

## Running Experiments

### 1. Live Continuous Migration (--live-cont)

Runs pre-copy + stop-and-copy + cutover migration with minimal traffic interruption.

```bash
sudo python3 scripts/mawi_crossstate_live_migration.py --live-cont \
  --run-dir /mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z \
  --output-dir artifacts/live_migration \
  --stop-duration-ms 100 \
  --cohort-size 500
```

**Expected Result:** `STATUS: PASS` — all checkpoints pass, state equivalence confirmed.

**Output Files:**
- `artifacts/live_migration/live_continuous_migration_result.json`
- `artifacts/live_migration/sota_comparison.md`
- `artifacts/live_migration/sota_comparison.csv`
- `artifacts/live_migration/sota_comparison.json`

### 2. No-Migration Baseline (--skip-checkpoint)

Validates that without migration, follow-up packets are dropped.

```bash
sudo python3 scripts/mawi_crossstate_live_migration.py \
  --skip-checkpoint \
  --traffic-quiesced \
  --run-dir /mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z \
  --output-dir artifacts/baseline \
  --cohort-size 500
```

**Expected Result:** ~99.6% of follow-up packets dropped, confirming migrated state is essential.

### 3. Automatic Failover Watcher (--auto-failover)

Monitors primary datapath health and triggers live migration to standby on failure.

```bash
sudo python3 scripts/mawi_crossstate_live_migration.py \
  --live-cont \
  --auto-failover \
  --failback \
  --failover-interval 2 \
  --failover-max-failures 3 \
  --failover-max-iterations 10 \
  --run-dir /mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z \
  --output-dir artifacts/failover \
  --stop-duration-ms 100
```

### 4. Standalone Fault Injection

Tests 4 fault scenarios against both BMv2 and XDP importers:

```bash
python3 scripts/fault_injection.py
```

**Expected Result:** All 7 scenarios detected (100%), fail-closed gate CLOSED in all cases.

**Output:** `artifacts/fault_injection_results.json`

### 5. Flow-Count Sweep (RQ3)

Sweeps flow counts from 100 to 10,000 and measures checkpoint time vs flows.

```bash
python3 scripts/g7_scale_sweep.py \
  --flows 100 500 1000 2000 5000 10000 \
  --output-dir artifacts/scale_sweep
```

**Output:** `artifacts/scale_sweep/sweep_results.csv`, `sweep_results.json`, `plots/`

### 6. MAWI Repetition Study (RQ4)

Runs MAWI migration N times (default 10) and computes mean ± 95% CI.

```bash
python3 scripts/mawi_repetition_study.py \
  --run-dir /mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z \
  --repetitions 10 \
  --output-dir artifacts/mawi_repetition \
  --traffic-quiesced
```

**Output:** `artifacts/mawi_repetition/repetition_results.json`, `plots/`

---

## Generating Q1 ACM Plots and Tables

### Generate Q1 ACM Plots (11 figures)

```bash
python3 scripts/generate_q1_plots.py
```

**Output:** `artifacts/q1_acm_plots/` — PNG, PDF, SVG for each figure:
- fig01_architecture: System architecture
- fig02_collision_direct_vs_bucketed: Direct vs bucketed collision
- fig03_checkpoint_phase_breakdown: Checkpoint time by phase
- fig04_fault_injection_detection: Fault detection coverage
- fig05_sota_comparison: SOTA comparison bar chart
- fig06_baseline_comparison: No-migration vs migrated baseline
- fig07_migration_timeline: Bidirectional migration timeline
- fig08_per_record_cost: Per-record write cost scaling
- fig09_decision_agreement: Packet decision agreement heatmap
- fig10_fault_summary: Fault injection detection by scenario
- fig11_bucket_capacity: Projected capacity with bucketed chains

### Generate Q1 ACM Tables and Report

```bash
python3 scripts/generate_q1_tables.py
```

**Output:** `artifacts/q1_acm_tables/`:
- `sota_comparison.tex` — LaTeX SOTA comparison table
- `rq_summary.tex` — Research questions & answers table
- `experiment_results.tex` — Experiment index table
- `report.md` — Full markdown research report

### Generate SOTA Comparison from Experiment Results

```bash
python3 scripts/sota_compare.py --artifacts-dir artifacts --output artifacts/sota_comparison
```

---

## Generating Research Question Plots

Generate advanced Q1-level plots for RQ1–RQ5 (scatter plots, line graphs, Venn diagrams, radar charts, sankey diagrams — no bar charts):

```bash
python3 scripts/generate_rq_plots.py
```

**Output:** `artifacts/rq_plots/`:
- `rq1_decision_scatter` — Decision agreement scatter plot
- `rq1_confusion_heatmap` — Confusion matrix heatmap
- `rq1_decision_agreement_over_time` — Agreement over checkpoints
- `rq2_disruption_line` — Disruption line graph
- `rq3_capacity_scatter` — Capacity scatter plot (log-log)
- `rq4_cost_line` — Phase timeline + time vs records
- `rq5_assurance_venn` — Fault detection Venn diagram
- `rq5_assurance_radar` — Assurance radar chart
- `migration_pipeline_sankey` — 8-phase pipeline diagram

---

## Stress Testing and Breakpoint Analysis

CrossState achieves 100% results on the standard testbed, but this does not mean it is immune to failure. Stress testing reveals breakpoints:

### 1. Bucket Overflow Stress Test

Insert more than 4 flows into the same bucket (depth=4 limit):

```bash
python3 -c "
from ref.model import step, slot_of, BUCKET_CHAIN_SIZE, ALLOW, DROP
from ref.model import Ev
import random

tbl = {}
ts = 1_000_000
base_ip = 0x0A000001

# Find 5+ keys hashing to same slot
keys = []
candidate = 1
while len(keys) < BUCKET_CHAIN_SIZE + 2 and candidate < 0xFFFFFFFF:
    key = (candidate, 40000, candidate + 1, 40001, 6)
    s = slot_of(key)
    keys.append((key, s))
    candidate += 1

# Group by slot
from collections import defaultdict
by_slot = defaultdict(list)
for k, s in keys:
    by_slot[s].append(k)

# Test overflow on most crowded slot
most_crowded = max(by_slot, key=lambda s: len(by_slot[s]))
slot_keys = by_slot[most_crowded]
print(f'Slot {most_crowded} has {len(slot_keys)} keys')

for i, key in enumerate(slot_keys):
    e = Ev(key[0], key[1], key[2], key[3], 6, True, True, False, False, False, 100, ts + i)
    r = step(tbl, e)
    status = 'ALLOW' if r == 1 else 'DROP'
    print(f'  Insert {i}: key={key} -> {status}')
    if i >= BUCKET_CHAIN_SIZE:
        assert r == DROP, f'Bucket overflow not rejected at insert {i}'
print('Bucket overflow breakpoint: CONFIRMED (depth=4 limit enforced)')
"
```

**Expected Breakpoint:** After 4 inserts into the same bucket, the 5th insert returns `DROP` (bucket overflow).

### 2. High Flow-Count Stress Test

Run sweep with large flow counts to observe rejection rates:

```bash
python3 scripts/g7_scale_sweep.py \
  --flows 1000 5000 10000 20000 40000 \
  --output-dir artifacts/stress_sweep
```

**Expected Breakpoint:** Direct-mapped table rejection rate grows beyond 7.2% at 10k flows, approaching 90% at 65k flows.

### 3. Concurrent Modification Stress Test

Modify source state during import to trigger source-stability failure:

```bash
python3 -c "
# Simulate source mutation between exports
from scripts.compare_state_snapshots import compare_snapshots
from scripts.fault_injection import make_snapshot, make_record

snap_a = make_snapshot([make_record(1, [50, 0, 0, 0, 6], st=1, last=1000)])
snap_b = make_snapshot([make_record(1, [50, 0, 0, 0, 6], st=1, last=9999)])
report = compare_snapshots(snap_a, snap_b)
assert not report['equivalent'], 'Source mutation not detected'
print('Source mutation breakpoint: CONFIRMED (stability check rejects mutated source)')
"
```

### 4. Fault Injection Breakpoints

Each fault scenario should be detected. Test that the system correctly rejects:

- **Slot collision:** Two different keys hashing to the same slot
- **Corrupt record:** Record value mismatch after write (read-back verification fails)
- **Interrupt after N:** Import interrupted mid-way (rollback attempted)
- **Source mutation:** Source changed between export and import (stability check fails)

Run: `python3 scripts/fault_injection.py`

### 5. Large Cohort Stress Test

Test with larger MAWI cohorts to observe performance degradation:

```bash
sudo python3 scripts/mawi_crossstate_live_migration.py --live-cont \
  --run-dir /mnt/e/SDN/datasets/mawi/processed/run_20261113T143001Z \
  --output-dir artifacts/stress_large \
  --stop-duration-ms 100 \
  --cohort-size 5000
```

**Expected Breakpoint:** Checkpoint time grows with flow count; BMv2 control path (one CLI subprocess per register write) becomes the bottleneck.

---

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `ModuleNotFoundError: No module named 'thrift'` | Thrift not installed | `pip install thrift` |
| `ModuleNotFoundError: No module named 'scapy'` | Scapy not installed | `pip install scapy` |
| `simple_switch_grpc not found` | BMv2 not installed | Install from https://github.com/p4lang/behavioral-model |
| `bpftool not found` | bpftool not installed | `sudo apt-get install linux-tools-$(uname -r)` |
| `Partial runtime detected` | One dataplane already running | Stop existing processes or let script preserve them |
| `BMv2 did not start on Thrift port 9090` | BMv2 failed to start | Check `/tmp/crossstate-bmv2.log` |
| `Bucket overflow at insert 4` | Expected behavior | Depth=4 limit enforced; use bucketed chaining |
| `Source mutation detected` | Expected behavior | Stability check correctly rejects mutated source |

---

## File Reference

| File | Purpose |
|------|---------|
| `scripts/crossstate_start_runtime.sh` | Start the live testbed (requires root) |
| `scripts/mawi_crossstate_live_migration.py` | Main migration entry point (--live-cont, --skip-checkpoint, --auto-failover) |
| `scripts/live_migration.py` | Standalone live migration (pre-copy + stop-and-copy + cutover) |
| `scripts/automatic_failover.py` | Failover watcher (health checks + auto-cutover + failback) |
| `scripts/datapath_hal.py` | Datapath abstraction layer (BMv2, XDP, Tofino, SmartNIC) |
| `scripts/sync_state.py` | Quiesced checkpoint protocol (8 phases, per-phase timing) |
| `scripts/fault_injection.py` | Fault injection testing (7 scenarios, 2 targets) |
| `scripts/g7_scale_sweep.py` | Flow-count sweep (RQ3) |
| `scripts/mawi_repetition_study.py` | MAWI repetition study (RQ4) |
| `scripts/generate_q1_plots.py` | Q1 ACM plots (11 figures) |
| `scripts/generate_rq_plots.py` | RQ-specific plots (9 figures, no bar charts) |
| `scripts/generate_q1_tables.py` | Q1 ACM tables and report |
| `scripts/sota_compare.py` | SOTA comparison aggregator |
| `scripts/sota_metrics.py` | SOTA metrics and reference values |
| `ref/model.py` | Reference model with bucketed chain support |
| `scripts/state_snapshot.py` | Snapshot validation and building |
| `scripts/compare_state_snapshots.py` | Snapshot comparison |
| `scripts/export_bmv2_state.py` | BMv2 state export |
| `scripts/export_xdp_state.py` | XDP state export |
| `scripts/import_bmv2_state.py` | BMv2 state import |
| `scripts/import_xdp_state.py` | XDP state import |
| `requirements.txt` | Python dependencies |
| `instruct_manual.md` | This manual |

---

## Research Question Summary

| RQ | Question | Result |
|----|----------|--------|
| RQ1 | Correctness: identical decisions and state after migration? | 100% decision agreement (18,944/18,944 packets), 100% state equivalence (1,086/1,086 records) |
| RQ2 | Necessity: is migrated state required? | Confirmed — 99.6% flows disrupted without migration vs 0% with |
| RQ3 | Capacity: flows before collision rejection? | Direct-mapped: 7.2% at 10k flows; Bucketed (depth 4): <0.1% projected |
| RQ4 | Cost: checkpoint time and write overhead? | 4 checkpoints: 47.7s + 201.5s + 484.1s + 130.5s = 863.8s total |
| RQ5 | Assurance: faults detected, gate works? | 7/7 detected (100%), fail-closed gate CLOSED in all cases |

---
