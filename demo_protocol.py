#!/usr/bin/env python3
"""Run a minimal end-to-end PPT-CLAMA protocol demo."""

from __future__ import annotations

import json

from protocol import run_demo


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
