# CrossState Master Evaluation

- Dataset: real (MAWI Samplepoint-F 2024-08-06 14:00 JST)
- Backend: simulate
- Requested packets: 5,000
- Available packets: 18,944
- Selected packets: 4,998
- Selected complete flows: 372
- Selection: whole-flow upper bound, capped at dataset size

## Correctness

{
  "simulation_bmv2_trace": {
    "count": 0,
    "TP_allow": 0,
    "TN_drop": 0,
    "FP_false_allow": 0,
    "FN_false_drop": 0,
    "accuracy_percent": null,
    "precision_percent": null,
    "recall_percent": null,
    "specificity_percent": null,
    "F1_percent": null,
    "false_allow_rate_percent": null,
    "false_drop_rate_percent": null,
    "MCC": null,
    "class_support_allow": 0,
    "class_support_drop": 0
  },
  "simulation_bmv2_controls": {
    "count": 0,
    "TP_allow": 0,
    "TN_drop": 0,
    "FP_false_allow": 0,
    "FN_false_drop": 0,
    "accuracy_percent": null,
    "precision_percent": null,
    "recall_percent": null,
    "specificity_percent": null,
    "F1_percent": null,
    "false_allow_rate_percent": null,
    "false_drop_rate_percent": null,
    "MCC": null,
    "class_support_allow": 0,
    "class_support_drop": 0
  },
  "simulation_xdp_trace": {
    "count": 0,
    "TP_allow": 0,
    "TN_drop": 0,
    "FP_false_allow": 0,
    "FN_false_drop": 0,
    "accuracy_percent": null,
    "precision_percent": null,
    "recall_percent": null,
    "specificity_percent": null,
    "F1_percent": null,
    "false_allow_rate_percent": null,
    "false_drop_rate_percent": null,
    "MCC": null,
    "class_support_allow": 0,
    "class_support_drop": 0
  },
  "simulation_xdp_controls": {
    "count": 0,
    "TP_allow": 0,
    "TN_drop": 0,
    "FP_false_allow": 0,
    "FN_false_drop": 0,
    "accuracy_percent": null,
    "precision_percent": null,
    "recall_percent": null,
    "specificity_percent": null,
    "F1_percent": null,
    "false_allow_rate_percent": null,
    "false_drop_rate_percent": null,
    "MCC": null,
    "class_support_allow": 0,
    "class_support_drop": 0
  }
}

## State

{
  "source": "in-memory reference simulation",
  "final_exact_state_equivalence": null,
  "bmv2_records": null,
  "xdp_records": null,
  "scope": "Both simulation tables use the Python reference model; not independent target validation."
}

## Migration

{
  "checkpoint_count": 0,
  "total_in_memory_copy_seconds": 0,
  "per_checkpoint": [],
  "scope": "In-memory dictionary copy only; not actual migration efficiency."
}

## Scope limits

Simulation is reference-model orchestration, not independent
datapath execution. Live throughput and latency are only reported
when the live runner instruments them. Traffic pause, NIC line-rate
throughput, one-way NIC latency, reordering, jitter, migration wire
bytes, and cryptographic migration security are not inferred
when unmeasured.
