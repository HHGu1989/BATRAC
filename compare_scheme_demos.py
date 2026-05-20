#!/usr/bin/env python3
"""Run the available protocol demos side by side for quick comparison."""

from __future__ import annotations

import argparse
import json
import time

from ecc import curve_for_security_model
from repeat_stats import run_repeated, write_payload_outputs
from threaded_protocol import run_threaded_demo as run_ppt_clama_demo
from threaded_bmae_protocol import run_threaded_bmae_demo
from threaded_cui_edge_batch_protocol import run_threaded_cui_demo
from threaded_ecroa_jpbc import run_threaded_ecroa_demo
from threaded_ma_edge_protocol import run_threaded_ma_demo
from threaded_psk_batch_clama_protocol import run_threaded_psk_batch_clama_demo
from threaded_shen_v2g_jpbc import run_threaded_shen_demo


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=6, help="Number of IoT devices for batch-oriented schemes.")
    parser.add_argument("--messages", type=int, default=12, help="Number of batch requests/messages.")
    parser.add_argument(
        "--security-model",
        default="128",
        choices=["80", "112", "128"],
        help="ECC security model / curve selection for the batch-oriented threaded schemes.",
    )
    parser.add_argument(
        "--tamper-index",
        type=int,
        default=-1,
        help="If >=0, tamper one entry in the batch-oriented schemes.",
    )
    parser.add_argument("--repeats", type=int, default=1, help="Run the same experiment multiple times and report mean/stddev.")
    parser.add_argument("--json-out", help="Optional path to write the full JSON payload.")
    parser.add_argument("--summary-csv", help="Optional path to write field,mean,stddev CSV.")
    parser.add_argument("--runs-csv", help="Optional path to write flattened per-run numeric CSV.")
    args = parser.parse_args()

    tamper_index = args.tamper_index if args.tamper_index >= 0 else None

    def _single_run(_idx: int):
        t0 = time.perf_counter()
        curve = curve_for_security_model(args.security_model)
        return {
            "ppt_clama": run_ppt_clama_demo(curve=curve),
            "bmae": run_threaded_bmae_demo(
                devices=args.devices,
                messages=args.messages,
                batch_size=0,
                tamper_index=tamper_index,
                curve=curve,
            ),
            "cui_edge_batch": run_threaded_cui_demo(
                devices=args.devices,
                messages=args.messages,
                tamper_index=tamper_index,
                curve=curve,
            ),
            "psk_bat_clama": run_threaded_psk_batch_clama_demo(
                devices=args.devices,
                messages=args.messages,
                batch_size=0,
                tamper_index=tamper_index,
                curve=curve,
            ),
            "ma_edge_update": run_threaded_ma_demo(
                devices=args.devices,
                messages=args.messages,
                tamper_index=tamper_index,
                curve=curve,
            ),
            "ecroa": run_threaded_ecroa_demo(
                devices=args.devices,
                messages=args.messages,
                domains=max(2, min(4, args.devices // 2 or 2)),
                tamper_index=tamper_index,
                curve=curve,
            ),
            "shen_v2g": run_threaded_shen_demo(
                devices=args.devices,
                messages=args.messages,
                tamper_index=tamper_index,
                curve=curve,
            ),
            "devices": args.devices,
            "messages": args.messages,
            "security_model": args.security_model,
            "tamper_index": tamper_index,
            "wall_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    payload = run_repeated(args.repeats, _single_run)
    write_payload_outputs(payload, args.json_out, args.summary_csv, args.runs_csv)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
