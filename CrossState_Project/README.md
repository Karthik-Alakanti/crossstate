# CrossState project bundle

codebase/   Full CrossState repository (P4, eBPF, spec, ref model, scripts, tests, artifacts, docs)
report/     IEEE two-column report v2: PDF + LaTeX source (+ figs); v1 kept for reference
analysis/   Scripts that produced the new report figures, baseline.json, EXPERIMENT_PLAN.md

## Rebuild the report
cd report && pdflatex crossstate_report_v2.tex && pdflatex crossstate_report_v2.tex
(needs TeX Live with tikz, mathptmx; IEEEtran is NOT required.)
Figures not in figs/ (mig_dur, etc.) are unused in v2.

## Re-run the analyses
Copy analysis/*.py into codebase/ and run from codebase/ root (they import ref/model.py):
  python3 collision_study.py   -> collision_load.png
  python3 analysis.py          -> baseline_drop, delta_full, time_per_record, parity PNGs + baseline.json
analysis.py reads the MAWI run folder (RUN / LIVE variables at its top): edit those two paths
to where your mawi_runs data lives. Needs numpy, pandas, matplotlib.

## Not included
The raw experiment archives you uploaded (mawi_runs.zip, Simulation_results.zip) - you already have them.
Pending experiments: analysis/EXPERIMENT_PLAN.md
