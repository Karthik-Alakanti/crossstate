# CrossState — Final Validation Report

## Implementations
- P4 v1model firewall running on BMv2.
- Linux XDP/eBPF firewall.
- Shared reference model and semantic contract.

## Validated milestones
- G0–G4: Reference model, CRC, target implementations,
  differential validation, state snapshots and import/export.
- G5: Shadow gates, safe new-flow handling, bidirectional
  checkpoint synchronization and source stability verification.
- G5.3: Actual bidirectional state migration and manually
  controlled cutover/cutback.
- G6: Runtime expiry, reopening, shadow behavior, readiness
  recovery, CLOSED-state enforcement and final equivalence.

## Final G6 runtime results
- Expired ACK rejected on both targets.
- Expired flow reopened by SYN on both targets.
- Unsynchronized shadow records skipped without mutation.
- Synchronized shadow records allowed.
- Readiness markers cleared and checkpoint recovery verified.
- RST transitions to CLOSED.
- Packets on CLOSED flows rejected.
- Final snapshots: 86 records on each target.
- Exact state equivalence: PASS.
- All 86 records marked ready on both targets.

## Automated regression
Run:
    python -m pytest tests -q

Latest observed result: 67 passed.

## Scope and limitations
- Synchronization uses quiesced checkpoints, not continuous
  live replication.
- Traffic quiescence is operator-acknowledged.
- BMv2 register exports are not atomic snapshots.
- Cutover/cutback are manually steered, not automatic failover.
- Fail-closed readiness clearing and recovery were exercised.
  An actual interrupted partial-import fault was not injected
  in the final G6 runtime experiment.
- No production NIC line-rate or hardware performance claim
  is made.

## Research extensions
Future evaluation should measure migration duration,
per-record cost, throughput, packet latency, scalability,
and interruption time across larger state tables.
