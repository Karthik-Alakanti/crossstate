#!/usr/bin/env python3

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts" / "g1"

JSON_FILE = ART / "g1_results.json"
CSV_FILE = ART / "g1_results.csv"


STATE_NAMES = {
    0: "EMPTY",
    1: "NEW",
    2: "EST",
    3: "CLOSED",
}


def load_results():
    with JSON_FILE.open() as f:
        data = json.load(f)

    df = pd.read_csv(CSV_FILE)

    return data, df


def plot_verdict_agreement(df):
    fig, ax = plt.subplots(figsize=(10, 5))

    x = range(len(df))

    oracle = [
        1 if x == "ALLOW" else 0
        for x in df["oracle_verdict"]
    ]

    bmv2 = [
        1 if x == "ALLOW" else 0
        for x in df["bmv2_verdict"]
    ]

    ax.plot(
        x,
        oracle,
        marker="o",
        linewidth=2,
        label="Reference model",
    )

    ax.plot(
        x,
        bmv2,
        marker="x",
        linewidth=2,
        linestyle="--",
        label="BMv2",
    )

    ax.set_yticks([0, 1])
    ax.set_yticklabels(["DROP", "ALLOW"])

    ax.set_xlabel("Tested packet event")
    ax.set_ylabel("Verdict")
    ax.set_title("Reference vs BMv2 Packet Verdicts")

    ax.legend()
    ax.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(
        ART / "verdict_agreement.png",
        dpi=300,
        bbox_inches="tight",
    )
    plt.close(fig)


def plot_final_state_comparison(data):
    rows = [
        x for x in data["results"]
        if x.get("event") == "FINAL_STATE"
    ]

    traces = [
        x["trace"]
        for x in rows
    ]

    oracle_states = [
        STATE_NAMES.get(
            x["oracle_record"]["st"]
            if x["oracle_record"] is not None
            else 0,
            "UNKNOWN",
        )
        for x in rows
    ]

    bmv2_states = [
        STATE_NAMES.get(
            x["bmv2_record"]["st"]
            if x["bmv2_record"] is not None
            else 0,
            "UNKNOWN",
        )
        for x in rows
    ]

    state_to_num = {
        "EMPTY": 0,
        "NEW": 1,
        "EST": 2,
        "CLOSED": 3,
    }

    x = list(range(len(traces)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(11, 5))

    ax.bar(
        [i - width / 2 for i in x],
        [state_to_num[s] for s in oracle_states],
        width,
        label="Reference model",
    )

    ax.bar(
        [i + width / 2 for i in x],
        [state_to_num[s] for s in bmv2_states],
        width,
        label="BMv2",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(traces, rotation=20, ha="right")

    ax.set_yticks([0, 1, 2, 3])
    ax.set_yticklabels(
        ["EMPTY", "NEW", "EST", "CLOSED"]
    )

    ax.set_ylabel("Final state")
    ax.set_title("Final State: Reference vs BMv2")

    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)

    fig.tight_layout()
    fig.savefig(
        ART / "final_state_comparison.png",
        dpi=300,
        bbox_inches="tight",
    )
    plt.close(fig)


def plot_trace_summary(data):
    rows = [
        x for x in data["results"]
        if x.get("event") == "FINAL_STATE"
    ]

    traces = [
        x["trace"]
        for x in rows
    ]

    passed = [
        1 if x["trace_pass"] else 0
        for x in rows
    ]

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.bar(traces, passed)

    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["FAIL", "PASS"])

    ax.set_ylabel("Trace result")
    ax.set_title("G1 Trace Results")

    ax.grid(True, axis="y", alpha=0.3)

    plt.xticks(rotation=20, ha="right")

    fig.tight_layout()
    fig.savefig(
        ART / "trace_summary.png",
        dpi=300,
        bbox_inches="tight",
    )
    plt.close(fig)


def plot_special_cases(data):
    df = pd.read_csv(CSV_FILE)

    special = []

    for trace_name in [
        "T4_LAZY_EXPIRY",
        "T5_COLLISION",
    ]:
        trace = df[df["trace"] == trace_name]

        for _, row in trace.iterrows():
            special.append(
                {
                    "trace": trace_name,
                    "event": int(row["event"]),
                    "verdict": row["oracle_verdict"],
                }
            )

    special_df = pd.DataFrame(special)

    fig, ax = plt.subplots(figsize=(9, 5))

    labels = [
        f"{r.trace.replace('T4_LAZY_EXPIRY', 'Expiry').replace('T5_COLLISION', 'Collision')} "
        f"E{r.event}"
        for r in special_df.itertuples()
    ]

    values = [
        1 if x == "ALLOW" else 0
        for x in special_df["verdict"]
    ]

    ax.bar(labels, values)

    ax.set_ylim(0, 1.2)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["DROP", "ALLOW"])

    ax.set_ylabel("Reference verdict")
    ax.set_title("Expiry and Collision Test Cases")

    ax.grid(True, axis="y", alpha=0.3)

    plt.xticks(rotation=25, ha="right")

    fig.tight_layout()
    fig.savefig(
        ART / "special_cases.png",
        dpi=300,
        bbox_inches="tight",
    )
    plt.close(fig)


def main():
    ART.mkdir(parents=True, exist_ok=True)

    data, df = load_results()

    plot_verdict_agreement(df)
    plot_final_state_comparison(data)
    plot_trace_summary(data)
    plot_special_cases(data)

    print("G1_PLOTS_CREATED")

    for name in [
        "verdict_agreement.png",
        "final_state_comparison.png",
        "trace_summary.png",
        "special_cases.png",
    ]:
        print(ART / name)


if __name__ == "__main__":
    main()
