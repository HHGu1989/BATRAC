#!/usr/bin/env python3
"""Python wrapper for the real JPBC-based Shen V2G threaded runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ecc import Curve


JAVA_HOME = Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home")
JAVA = JAVA_HOME / "bin" / "java"
JAVAC = JAVA_HOME / "bin" / "javac"
ROOT = Path(__file__).resolve().parent
JAVA_DIR = ROOT / "shen-java"
JAVA_FILE = JAVA_DIR / "ShenV2GThreadedRunner.java"
CLASS_FILE = JAVA_DIR / "ShenV2GThreadedRunner.class"
JARS_DIR = Path("/Users/liuxiang/Projects/jpbc-2.0.0/jars")


def _compile_if_needed():
    if not JAVA.exists() or not JAVAC.exists():
        raise RuntimeError("OpenJDK not found at the expected Homebrew path")
    if not JARS_DIR.exists():
        raise RuntimeError(f"JPBC jars directory not found: {JARS_DIR}")
    if CLASS_FILE.exists() and CLASS_FILE.stat().st_mtime >= JAVA_FILE.stat().st_mtime:
        return
    subprocess.run(
        [
            str(JAVAC),
            "-cp",
            str(JARS_DIR / "*"),
            str(JAVA_FILE),
        ],
        cwd=str(JAVA_DIR),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_threaded_shen_demo(
    devices: int = 8,
    messages: int = 16,
    tamper_index: int | None = None,
    curve: Curve | None = None,
) -> dict:
    _compile_if_needed()
    security_model = "128"
    if curve is not None:
        if curve.name == "secp160r1":
            security_model = "80"
        elif curve.name == "secp224r1":
            security_model = "112"
        elif curve.name == "secp256r1":
            security_model = "128"

    cmd = [
        str(JAVA),
        "-cp",
        f"{JAVA_DIR}:{JARS_DIR}/*",
        "ShenV2GThreadedRunner",
        "--devices",
        str(devices),
        "--messages",
        str(messages),
        "--security-model",
        security_model,
    ]
    if tamper_index is not None:
        cmd.extend(["--tamper-index", str(tamper_index)])
    completed = subprocess.run(
        cmd,
        cwd=str(JAVA_DIR),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout.strip())

