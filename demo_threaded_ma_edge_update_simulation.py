#!/usr/bin/env python3
"""Run a threaded simulation for Ma et al. (JSA 2025)."""

from __future__ import annotations

import argparse
import json
import time

from ecc import curve_for_security_model
from repeat_stats import run_repeated, write_payload_outputs
from threaded_ma_edge_protocol import run_threaded_ma_demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=8, help="Number of SD actors.")
    parser.add_argument("--messages", type=int, default=16, help="Number of messages to submit.")
    parser.add_argument(
        "--security-model",
        default="128",
        choices=["80", "112", "128"],
        help="ECC security model / curve selection for the threaded simulation.",
    )
    parser.add_argument("--tamper-index", type=int, default=-1, help="If >=0, tamper one queued packet.")
    parser.add_argument("--repeats", type=int, default=1, help="Run the same experiment multiple times and report mean/stddev.")
    parser.add_argument("--include-runs", action="store_true", help="Include detailed per-run results in stdout JSON.")
    parser.add_argument("--json-out", help="Optional path to write the full JSON payload.")
    parser.add_argument("--summary-csv", help="Optional path to write field,mean,stddev CSV.")
    parser.add_argument("--runs-csv", help="Optional path to write flattened per-run numeric CSV.")
    args = parser.parse_args()

    def _single_run(_idx: int):
        t0 = time.perf_counter()
        payload = run_threaded_ma_demo(
            devices=args.devices,
            messages=args.messages,
            tamper_index=(args.tamper_index if args.tamper_index >= 0 else None),
            curve=curve_for_security_model(args.security_model),
        )
        payload["security_model"] = args.security_model
        payload["wall_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return payload

    payload = run_repeated(args.repeats, _single_run, include_runs=(args.include_runs or bool(args.runs_csv)))
    write_payload_outputs(payload, args.json_out, args.summary_csv, args.runs_csv)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
