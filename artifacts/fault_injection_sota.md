# SOTA Comparison: CrossState vs Related Work

| System | Year | Platform | Downtime (ms) | Records written | Throughput (rec/s) | Packet loss (%) | Decision agreement (%) | State equivalence (%) | Rollback (%) | Per-record (ms) | Concurrent | Cross-platform | Verification |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CrossState | 2026 | BMv2 (P4) <-> XDP (eBPF) | n/a | 0 | n/a | n/a | 100.000 | n/a | 57.143 | n/a | no | yes | read_back |
| RedPlane | 2021 | Tofino switches | 950.000 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | yes | no | replication |
| Cora/Vela | 2024 | SoC SmartNIC <-> host/Arm CPU | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | yes | yes | none |
| SwitchNIC | 2025 | Tofino switch + ARM SmartNIC | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | yes | yes | none |

## Notes
- Downtime: traffic interruption during migration (quiesced window).
- Records written: state records transferred per migration cycle.
- Throughput: records written per second of migration wall time.
- Packet loss: follow-up packets dropped due to missing state.
- Decision agreement: datapath decisions matching reference model.
- State equivalence: source/destination tables identical after migration.
- Rollback: successful rollback rate on failed imports.
- Per-record: wall time spent writing one state record.
- Concurrent: supports migration while traffic flows.
- Cross-platform: works across heterogeneous targets (P4 <-> eBPF).
- Verification: none / read_back / full_equivalence / audit.

## Paper-Specific Measured Metrics (not in table above)

| Paper | Key Metrics |
|-------|-------------|
| RedPlane (SIGCOMM'21) | Recovery: 0.9-1.0s after switch failure; Per-packet overhead: <8µs (write-centric), negligible (read-centric); ASIC resources: <14%; Verification: TLA+ model-checked lease protocol |
| Cora/Vela (arXiv'24) | CPU savings: 62.9%-91.9% vs best baseline; Throughput improvement: 15.2%-120.8% (NATLB); Lock contention: 5-10x performance variation for similar memory ops; Verification: none (compiler optimization) |
| SwitchNIC (CoNEXT'25) | P99 latency: 6µs; Fast-path: ~350ns; Energy efficiency: 5.2× better than server-based; Processing latency: 6.4× better than server-based; Traffic churn: 100k new flows/min tolerated; Verification: none (strong consistency via on-path replication) |

n/a = not reported in the source paper (qualitative guarantee only). CrossState values come from experiment outputs.