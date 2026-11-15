# Pending experiments (need the BMv2 + XDP testbed)

The v2 report is complete for everything computable from the uploaded runs and the repo.
These four items are listed as "Planned extensions" in Section VIII; running them will turn
them into results. Priority order = cheapest first.

## 1. Per-phase timing (RQ4)  -- ~1 hour
Add `time.perf_counter()` around these steps in `scripts/sync_state.py`
(export source, export destination, compare, plan, apply/import, verify, stability re-export,
final export) and write them into the audit JSON as `phase_seconds`.
Output: stacked bar per checkpoint (replaces/extends Fig. 8).

## 2. Flow-count sweep (RQ3/RQ4)
`scripts/g7_scale_1000.py` hard-codes 1,000 flows. Parametrize the flow count
(100, 500, 1k, 2k, 5k, 10k) and rerun the 4-checkpoint schedule.
Record: checkpoint seconds, records written, equivalence pass/fail, collision rejections.
Output: checkpoint time vs flows (log-x) and records written vs flows.
Note: at 10k flows expect ~7% collision rejections (Fig. 6); pick keys or count only accepted flows.

## 3. Fault injection (RQ5)  -- the most valuable addition
Using `scripts/import_bmv2_state.py` (apply_plan has the rollback path) and `import_xdp_state.py`:
 a. interrupt the import after N records (kill / raise) -> expect gate stays closed, rollback attempted
 b. corrupt one record value before write -> expect read-back or equivalence check fails
 c. mutate the source between the two exports -> expect stability check fails
 d. force a slot collision (different key, same slot) -> expect conflict reported
Output: table "fault -> detected? -> gate state -> rollback result" (replaces a planned-extension bullet).

## 4. Repetitions
Rerun E2 (MAWI, 4 checkpoints) 10 times; report mean +/- 95% CI of checkpoint seconds
(box plot). Needs a loop around `scripts/mawi_crossstate_live_migration.py`.

## Optional: live no-migration baseline
Run the MAWI schedule with `--skip-checkpoint` (or equivalent) on the real targets so that the
current model-based baseline (Fig. 5 / Table IX) is confirmed on hardware-in-the-loop.
