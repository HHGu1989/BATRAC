#!/usr/bin/env python3
"""Run an N-device concurrent registration/authentication simulation."""

from __future__ import annotations

import argparse
import json
import statistics
import time

from ecc import curve_for_security_model
from repeat_stats import run_repeated, write_payload_outputs
from threaded_protocol import ThreadedSimulation, make_random_pairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", type=int, default=8, help="Number of device actors to simulate.")
    parser.add_argument("--sessions", type=int, default=12, help="Number of concurrent authentication sessions.")
    parser.add_argument("--seed", type=int, default=20250306, help="Seed for random pairing.")
    parser.add_argument(
        "--security-model",
        default="128",
        choices=["80", "112", "128"],
        help="ECC security model / curve selection for the threaded simulation.",
    )
    parser.add_argument("--repeats", type=int, default=1, help="Run the same experiment multiple times and report mean/stddev.")
    parser.add_argument("--include-runs", action="store_true", help="Include detailed per-run results in stdout JSON.")
    parser.add_argument("--json-out", help="Optional path to write the full JSON payload.")
    parser.add_argument("--summary-csv", help="Optional path to write field,mean,stddev CSV.")
    parser.add_argument("--runs-csv", help="Optional path to write flattened per-run numeric CSV.")
    args = parser.parse_args()

    def _single_run(_idx: int):
        device_ids = [f"device-{index:02d}" for index in range(1, args.devices + 1)]
        simulation = ThreadedSimulation(device_ids, curve=curve_for_security_model(args.security_model))
        simulation.start()
        try:
            t0 = time.perf_counter()
            bundles = simulation.register_all()
            t1 = time.perf_counter()
            simulation.distribute_peer_views()
            t2 = time.perf_counter()
            pairs = make_random_pairs(device_ids, args.sessions, seed=args.seed)
            results = simulation.authenticate_pairs(pairs, start_timestamp=100)
            t3 = time.perf_counter()
            compact_results = [
                {
                    "initiator_rid": item["initiator_rid"],
                    "responder_rid": item["responder_rid"],
                    "session_hint": item["session_hint"],
                    "session_key_sha256": item["session_key_sha256"],
                }
                for item in results
            ]
            traces = {
                rid: simulation.trace_identity(bundle.pid, bundle.P_i)
                for rid, bundle in list(bundles.items())[: min(3, len(bundles))]
            }
            return {
                "devices": args.devices,
                "sessions": args.sessions,
                "security_model": args.security_model,
                "curve": simulation.kgc.curve.name,
                "pairs": pairs,
                "completed_sessions": len(results),
                "all_session_keys_present": all("session_key_sha256" in item for item in results),
                "register_ms": round((t1 - t0) * 1000.0, 3),
                "peer_distribution_ms": round((t2 - t1) * 1000.0, 3),
                "authentication_ms": round((t3 - t2) * 1000.0, 3),
                "avg_request_auth_ms": round(statistics.mean(item["request_auth_ms"] for item in results), 3) if results else 0.0,
                "avg_key_agreement_ms": round(statistics.mean(item["key_agreement_ms"] for item in results), 3) if results else 0.0,
                "avg_session_total_ms": round(statistics.mean(item["session_total_ms"] for item in results), 3) if results else 0.0,
                "sample_traces": traces,
                "sample_results": compact_results[: min(5, len(compact_results))],
                "mode": "threaded-concurrent-simulation",
                "wall_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        finally:
            simulation.stop()

    payload = run_repeated(args.repeats, _single_run, include_runs=(args.include_runs or bool(args.runs_csv)))
    write_payload_outputs(payload, args.json_out, args.summary_csv, args.runs_csv)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
