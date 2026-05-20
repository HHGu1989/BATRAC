#!/usr/bin/env python3
"""Reproduce the Section 5 evaluation methodology for PPT-CLAMA.

This script is intentionally dependency-free. It benchmarks ECC scalar
multiplication on three security levels, calibrates a pairing proxy for
pairing-based baselines, and generates CSV/SVG outputs for:

1. Running time vs. authentication attempts under simulation
2. Average running time by security model
3. Communication overhead comparison

The resulting numbers reproduce the paper's method, not the exact published
figures, because some competitor table cells are not recoverable from the local
PDF OCR output available in this environment.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int


CURVES = {
    "secp160r1": Curve(
        name="secp160r1",
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC,
        b=0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45,
        gx=0x4A96B5688EF573284664698968C38BB913CBFC82,
        gy=0x23A628553168947D59DCC912042351377AC5FB32,
        n=0x0100000000000000000001F4C8F927AED3CA752257,
    ),
    "secp224r1": Curve(
        name="secp224r1",
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
        b=0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
        gx=0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
        gy=0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
        n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    ),
    "secp256r1": Curve(
        name="secp256r1",
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
}

INFINITY = (None, None)


def inv_mod(k: int, p: int) -> int:
    return pow(k, -1, p)


def point_add(curve: Curve, p1, p2):
    if p1 == INFINITY:
        return p2
    if p2 == INFINITY:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return INFINITY
    if p1 == p2:
        m = (3 * x1 * x1 + curve.a) * inv_mod(2 * y1 % curve.p, curve.p)
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % curve.p, curve.p)
    m %= curve.p
    x3 = (m * m - x1 - x2) % curve.p
    y3 = (m * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def scalar_mult(curve: Curve, k: int, point):
    if k % curve.n == 0 or point == INFINITY:
        return INFINITY
    if k < 0:
        x, y = point
        return scalar_mult(curve, -k, (x, (-y) % curve.p))
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1
    return result


def benchmark_scalar_mult(curve: Curve, iterations: int, seed: int) -> float:
    rng = random.Random(seed)
    base_point = (curve.gx, curve.gy)
    samples = []
    for _ in range(iterations):
        k = rng.randrange(1, curve.n)
        start = time.perf_counter()
        scalar_mult(curve, k, base_point)
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.mean(samples)


def load_config(path: Path) -> dict:
    return json.loads(path.read_text())


def runtime_ms_for_attempts(scheme_meta: dict, scalar_ms: float, pairing_proxy: float, attempts: int) -> float:
    """Compute runtime for one scheme under a given number of attempts.

    Supported models:
    1) Legacy linear model:
       runtime = attempts * (scalar_mults + pairings * proxy)
    2) Batch model with constant setup / aggregation overhead:
       runtime = (base_scalar_mults + per_attempt_scalar_mults * attempts) * scalar
               + (base_pairings + per_attempt_pairings * attempts) * pairing
    """
    if "runtime_model" in scheme_meta:
        model = scheme_meta["runtime_model"]
        base_scalar = float(model.get("base_scalar_mults", 0.0))
        per_scalar = float(model.get("per_attempt_scalar_mults", 0.0))
        base_pairings = float(model.get("base_pairings", 0.0))
        per_pairings = float(model.get("per_attempt_pairings", 0.0))
        return scalar_ms * (base_scalar + per_scalar * attempts) + scalar_ms * pairing_proxy * (
            base_pairings + per_pairings * attempts
        )

    return scalar_ms * attempts * (
        float(scheme_meta["scalar_mults"]) + float(scheme_meta["pairings"]) * pairing_proxy
    )


def write_csv(path: Path, rows, headers):
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def color_for(index: int) -> str:
    colors = [
        "#0f766e",
        "#b45309",
        "#1d4ed8",
        "#7c3aed",
        "#be123c",
        "#4d7c0f",
        "#0369a1",
        "#92400e",
        "#334155",
        "#166534",
    ]
    return colors[index % len(colors)]


def svg_line_chart(path: Path, title: str, x_label: str, y_label: str, series: dict[str, list[tuple[float, float]]]):
    width = 960
    height = 560
    margin = 70
    all_x = [x for points in series.values() for x, _ in points]
    all_y = [y for points in series.values() for _, y in points]
    x_min, x_max = min(all_x), max(all_x)
    y_min, y_max = 0.0, max(all_y) * 1.1

    def sx(x):
        if x_max == x_min:
            return margin
        return margin + (x - x_min) * (width - 2 * margin) / (x_max - x_min)

    def sy(y):
        if y_max == y_min:
            return height - margin
        return height - margin - (y - y_min) * (height - 2 * margin) / (y_max - y_min)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="#fffdf8"/>',
        f'<text x="{width/2}" y="32" text-anchor="middle" font-size="22" font-family="Menlo, monospace">{title}</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="#334155" stroke-width="2"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="#334155" stroke-width="2"/>',
        f'<text x="{width/2}" y="{height-18}" text-anchor="middle" font-size="14" font-family="Menlo, monospace">{x_label}</text>',
        f'<text x="22" y="{height/2}" text-anchor="middle" font-size="14" font-family="Menlo, monospace" transform="rotate(-90 22 {height/2})">{y_label}</text>',
    ]

    for tick in range(6):
        y = y_min + (y_max - y_min) * tick / 5.0
        py = sy(y)
        parts.append(f'<line x1="{margin}" y1="{py}" x2="{width-margin}" y2="{py}" stroke="#e2e8f0" stroke-width="1"/>')
        parts.append(f'<text x="{margin-10}" y="{py+4}" text-anchor="end" font-size="12" font-family="Menlo, monospace">{y:.2f}</text>')
    for tick in sorted(set(all_x)):
        px = sx(tick)
        parts.append(f'<line x1="{px}" y1="{height-margin}" x2="{px}" y2="{height-margin+6}" stroke="#334155" stroke-width="1"/>')
        parts.append(f'<text x="{px}" y="{height-margin+22}" text-anchor="middle" font-size="12" font-family="Menlo, monospace">{tick:g}</text>')

    legend_x = width - margin - 180
    legend_y = margin + 12
    for idx, (label, points) in enumerate(series.items()):
        color = color_for(idx)
        coords = " ".join(f"{sx(x)},{sy(y)}" for x, y in points)
        parts.append(f'<polyline fill="none" stroke="{color}" stroke-width="2.5" points="{coords}"/>')
        for x, y in points:
            parts.append(f'<circle cx="{sx(x)}" cy="{sy(y)}" r="3.5" fill="{color}"/>')
        ly = legend_y + idx * 18
        parts.append(f'<line x1="{legend_x}" y1="{ly}" x2="{legend_x+18}" y2="{ly}" stroke="{color}" stroke-width="3"/>')
        parts.append(f'<text x="{legend_x+24}" y="{ly+4}" font-size="12" font-family="Menlo, monospace">{label}</text>')

    parts.append("</svg>")
    path.write_text("\n".join(parts))


def svg_bar_chart(path: Path, title: str, y_label: str, values: dict[str, float]):
    width = 960
    height = 560
    margin = 70
    y_max = max(values.values()) * 1.15 if values else 1.0
    bar_gap = 14
    bar_width = max(22, (width - 2 * margin - bar_gap * (len(values) - 1)) / max(1, len(values)))

    def sy(y):
        return height - margin - y * (height - 2 * margin) / y_max

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="#fffdf8"/>',
        f'<text x="{width/2}" y="32" text-anchor="middle" font-size="22" font-family="Menlo, monospace">{title}</text>',
        f'<line x1="{margin}" y1="{height-margin}" x2="{width-margin}" y2="{height-margin}" stroke="#334155" stroke-width="2"/>',
        f'<line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height-margin}" stroke="#334155" stroke-width="2"/>',
        f'<text x="22" y="{height/2}" text-anchor="middle" font-size="14" font-family="Menlo, monospace" transform="rotate(-90 22 {height/2})">{y_label}</text>',
    ]
    for tick in range(6):
        y = y_max * tick / 5.0
        py = sy(y)
        parts.append(f'<line x1="{margin}" y1="{py}" x2="{width-margin}" y2="{py}" stroke="#e2e8f0" stroke-width="1"/>')
        parts.append(f'<text x="{margin-10}" y="{py+4}" text-anchor="end" font-size="12" font-family="Menlo, monospace">{y:.2f}</text>')

    x = margin
    for idx, (label, value) in enumerate(values.items()):
        h = height - margin - sy(value)
        y = sy(value)
        color = color_for(idx)
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_width}" height="{h}" fill="{color}"/>')
        parts.append(f'<text x="{x + bar_width/2}" y="{height-margin+16}" text-anchor="middle" font-size="11" font-family="Menlo, monospace" transform="rotate(20 {x + bar_width/2} {height-margin+16})">{label}</text>')
        parts.append(f'<text x="{x + bar_width/2}" y="{y-6}" text-anchor="middle" font-size="11" font-family="Menlo, monospace">{value:.2f}</text>')
        x += bar_width + bar_gap

    parts.append("</svg>")
    path.write_text("\n".join(parts))


def simulate(config: dict, out_dir: Path, benchmark_iterations: int, seed: int):
    out_dir.mkdir(parents=True, exist_ok=True)
    primitive_rows = []
    scalar_costs = {}
    pairing_proxy = config["pairing_proxy_multiplier"]

    for security_model, meta in config["security_models"].items():
        curve = CURVES[meta["curve"]]
        scalar_ms = benchmark_scalar_mult(curve, benchmark_iterations, seed + int(security_model))
        scalar_costs[security_model] = scalar_ms
        primitive_rows.append(
            {
                "security_model": security_model,
                "curve": curve.name,
                "scalar_mult_ms": round(scalar_ms, 6),
                "pairing_proxy_ms": round(scalar_ms * pairing_proxy, 6),
            }
        )

    write_csv(out_dir / "primitive_benchmarks.csv", primitive_rows, ["security_model", "curve", "scalar_mult_ms", "pairing_proxy_ms"])

    runtime_rows = []
    avg_rows = []
    representative_attempts = max(config["attempt_counts"])
    for security_model, scalar_ms in scalar_costs.items():
        scheme_avg = {}
        for scheme_name, scheme_meta in config["schemes"].items():
            representative_runtime_ms = runtime_ms_for_attempts(
                scheme_meta, scalar_ms, pairing_proxy, representative_attempts
            )
            per_attempt_ms = representative_runtime_ms / representative_attempts
            scheme_avg[scheme_name] = per_attempt_ms
            avg_rows.append(
                {
                    "security_model": security_model,
                    "scheme": scheme_name,
                    "kind": scheme_meta["kind"],
                    "per_attempt_ms": round(per_attempt_ms, 6),
                }
            )
            for attempts in config["attempt_counts"]:
                runtime_ms = runtime_ms_for_attempts(scheme_meta, scalar_ms, pairing_proxy, attempts)
                runtime_rows.append(
                    {
                        "security_model": security_model,
                        "scheme": scheme_name,
                        "kind": scheme_meta["kind"],
                        "attempts": attempts,
                        "runtime_ms": round(runtime_ms, 6),
                    }
                )
        series = {
            name: [(row["attempts"], row["runtime_ms"]) for row in runtime_rows if row["security_model"] == security_model and row["scheme"] == name]
            for name in config["schemes"]
        }
        svg_line_chart(
            out_dir / f"runtime_{security_model}bit.svg",
            f"Section 5 Reproduction: Runtime Under {security_model}-bit Model",
            "Authentication Attempts",
            "Runtime (ms)",
            series,
        )
        avg_values = {
            row["scheme"]: row["per_attempt_ms"]
            for row in avg_rows
            if row["security_model"] == security_model
        }
        svg_bar_chart(
            out_dir / f"avg_runtime_{security_model}bit.svg",
            f"Average Runtime Under {security_model}-bit Model",
            "Per-attempt Runtime (ms)",
            avg_values,
        )

    write_csv(out_dir / "runtime_simulation.csv", runtime_rows, ["security_model", "scheme", "kind", "attempts", "runtime_ms"])
    write_csv(out_dir / "average_runtime.csv", avg_rows, ["security_model", "scheme", "kind", "per_attempt_ms"])

    comm_rows = []
    for scheme_name, scheme_meta in config["schemes"].items():
        if scheme_meta["comm_bits"] is None:
            continue
        comm_rows.append(
            {
                "scheme": scheme_name,
                "comm_bits": scheme_meta["comm_bits"],
            }
        )
    write_csv(out_dir / "communication_overhead.csv", comm_rows, ["scheme", "comm_bits"])
    svg_bar_chart(
        out_dir / "communication_overhead.svg",
        "Communication Overhead Reproduction",
        "Bits",
        {row["scheme"]: row["comm_bits"] for row in comm_rows},
    )

    summary_lines = []
    summary_lines.append("# Scheme Simulation Summary")
    summary_lines.append("")
    summary_lines.append("## Method")
    summary_lines.append("")
    summary_lines.append("- Benchmarked ECC scalar multiplication locally on secp160r1, secp224r1, and secp256r1 as proxies for the 80-, 112-, and 128-bit models used in the paper.")
    summary_lines.append(f"- Used a pairing proxy multiplier of {pairing_proxy:.2f}x scalar multiplication for pairing-based competitors.")
    summary_lines.append("- Computed scheme runtime by multiplying local primitive timings with per-scheme operation counts from Section 5.")
    summary_lines.append(f"- For schemes with a `runtime_model`, the average per-attempt bar uses the largest configured attempt count ({representative_attempts}) as the representative asymptotic point.")
    summary_lines.append("- Communication-overhead bars are generated directly from the `comm_bits` values in `schemes.json`.")
    summary_lines.append("- The generated numbers are local proxy results. They combine paper-stated counts with implementation-informed estimates for the newly added local schemes; they are useful for relative comparison, not as claimed paper figures.")
    summary_lines.append("")
    summary_lines.append("## Primitive Benchmarks")
    summary_lines.append("")
    for row in primitive_rows:
        summary_lines.append(
            f"- {row['security_model']}-bit ({row['curve']}): scalar multiplication {row['scalar_mult_ms']:.4f} ms, pairing proxy {row['pairing_proxy_ms']:.4f} ms"
        )
    summary_lines.append("")
    summary_lines.append("## Kind Means")
    summary_lines.append("")
    kinds = sorted({meta["kind"] for meta in config["schemes"].values()})
    for security_model in config["security_models"]:
        this_avg = {row["scheme"]: row["per_attempt_ms"] for row in avg_rows if row["security_model"] == security_model}
        kind_means = []
        for kind in kinds:
            names = [name for name, meta in config["schemes"].items() if meta["kind"] == kind]
            if not names:
                continue
            mean_value = statistics.mean(this_avg[name] for name in names)
            kind_means.append(f"{kind}={mean_value:.4f} ms")
        summary_lines.append(
            f"- {security_model}-bit: " + ", ".join(kind_means)
        )
    focus_schemes = config.get("focus_schemes", [])
    if focus_schemes:
        summary_lines.append("")
        summary_lines.append("## Focus Schemes")
        summary_lines.append("")
        for security_model in config["security_models"]:
            this_avg = {row["scheme"]: row["per_attempt_ms"] for row in avg_rows if row["security_model"] == security_model}
            ranking = sorted(this_avg.items(), key=lambda item: item[1])
            rank_map = {name: idx + 1 for idx, (name, _) in enumerate(ranking)}
            fastest_ms = ranking[0][1]
            for scheme_name in focus_schemes:
                if scheme_name not in this_avg:
                    continue
                delta = this_avg[scheme_name] - fastest_ms
                summary_lines.append(
                    f"- {security_model}-bit {scheme_name}: {this_avg[scheme_name]:.4f} ms per attempt, rank {rank_map[scheme_name]}/{len(ranking)}, delta vs fastest {delta:.4f} ms"
                )
    if comm_rows:
        summary_lines.append("")
        summary_lines.append("## Communication Overhead")
        summary_lines.append("")
        for row in sorted(comm_rows, key=lambda item: item["comm_bits"]):
            summary_lines.append(f"- {row['scheme']}: {row['comm_bits']} bits")
    (out_dir / "SUMMARY.md").write_text("\n".join(summary_lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default=Path(__file__).with_name("schemes.json"),
        type=Path,
        help="Path to scheme configuration JSON.",
    )
    parser.add_argument(
        "--out-dir",
        default=Path(__file__).with_name("results"),
        type=Path,
        help="Directory for generated CSV/SVG outputs.",
    )
    parser.add_argument(
        "--benchmark-iterations",
        default=8,
        type=int,
        help="Number of scalar multiplication benchmark samples per security model.",
    )
    parser.add_argument(
        "--seed",
        default=20250306,
        type=int,
        help="Random seed for deterministic scalar choices.",
    )
    args = parser.parse_args()
    simulate(load_config(args.config), args.out_dir, args.benchmark_iterations, args.seed)


if __name__ == "__main__":
    main()
