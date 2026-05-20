#!/usr/bin/env python3
"""Run the threaded actor-style PPT-CLAMA demo."""

from __future__ import annotations

import argparse
import json

from ecc import curve_for_security_model
from threaded_protocol import run_threaded_demo


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--security-model",
        default="128",
        choices=["80", "112", "128"],
        help="ECC security model / curve selection for the threaded two-party demo.",
    )
    args = parser.parse_args()
    payload = run_threaded_demo(curve=curve_for_security_model(args.security_model))
    payload["security_model"] = args.security_model
    print(json.dumps(payload, indent=2, sort_keys=True))
