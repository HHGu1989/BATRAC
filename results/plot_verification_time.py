#!/opt/homebrew/bin/python3.11
"""Plot online authentication total time with error-bar line charts."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1.inset_locator import inset_axes


ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "verification-time.csv"
OUT_DIR = Path(__file__).resolve().parent
DPI = 600

matplotlib.rcParams.update(
    {
        "font.size": 9,
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "axes.labelsize": 9,
        "axes.titlesize": 10,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 7.2,
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.04,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "mathtext.fontset": "stix",
    }
)

SCHEME_ORDER = [
    "BAT-CLAMA",
    "PPT-CLAMA",
    "BMAE",
    "Cui-Edge-Batch",
    "Ma-Edge-Update",
    "ECroA",
    "Shen-V2G",
]
LABELS = {
    "BAT-CLAMA": "BAT-CLAMA",
    "PPT-CLAMA": "PPT-CLAMA",
    "BMAE": "BMAE",
    "Cui-Edge-Batch": "Cui et al.",
    "Ma-Edge-Update": "Ma et al.",
    "ECroA": "ECroA",
    "Shen-V2G": "Shen et al.",
}
COLORS = {
    "BAT-CLAMA": "#D55E00",
    "PPT-CLAMA": "#4C78A8",
    "BMAE": "#59A14F",
    "Cui-Edge-Batch": "#E17C05",
    "Ma-Edge-Update": "#B279A2",
    "ECroA": "#76B7B2",
    "Shen-V2G": "#9C755F",
}
MARKERS = {
    "BAT-CLAMA": "o",
    "PPT-CLAMA": "s",
    "BMAE": "D",
    "Cui-Edge-Batch": "^",
    "Ma-Edge-Update": "v",
    "ECroA": "P",
    "Shen-V2G": "X",
}
COUNTS = [8, 16, 32, 64, 128]
SECURITY_MODELS = ["80", "112", "128"]


def read_rows() -> list[dict[str, str]]:
    with CSV_PATH.open() as handle:
        return list(csv.DictReader(handle))


def plot_for_security(rows: list[dict[str, str]], security_model: str):
    subset = [row for row in rows if row["security_model"] == security_model]
    by_key = {(row["scheme"], int(row["devices"])): row for row in subset}

    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    max_y = 0.0
    low_range_max = 0.0
    for scheme in SCHEME_ORDER:
        means = [float(by_key[(scheme, count)]["mean_ms"]) for count in COUNTS]
        stds = [float(by_key[(scheme, count)]["stddev_ms"]) for count in COUNTS]
        max_y = max(max_y, max(m + s for m, s in zip(means, stds)))
        if scheme not in {"ECroA", "Shen-V2G"}:
            low_range_max = max(low_range_max, max(m + s for m, s in zip(means, stds)))
        ax.errorbar(
            COUNTS,
            means,
            yerr=stds,
            label=LABELS[scheme],
            color=COLORS[scheme],
            marker=MARKERS[scheme],
            linewidth=2.0 if scheme == "BAT-CLAMA" else 1.35,
            markersize=5.0 if scheme == "BAT-CLAMA" else 4.1,
            capsize=2.2,
            elinewidth=0.8,
        )

    ax.set_xlabel("Number of Participating Devices")
    ax.set_ylabel("Online Authentication Time (ms)")
    ax.set_xticks(COUNTS)
    ax.set_title(f"Online Authentication Time at {security_model}-bit Security")
    ax.grid(axis="y", linestyle="--", linewidth=0.45, alpha=0.35)
    ax.grid(axis="x", linestyle=":", linewidth=0.35, alpha=0.18)
    ax.set_ylim(0, max_y * 1.08)
    ax.legend(ncol=4, frameon=False, loc="upper left")

    inset = inset_axes(ax, width="43%", height="46%", loc="center right", borderpad=1.0)
    for scheme in SCHEME_ORDER:
        if scheme in {"ECroA", "Shen-V2G"}:
            continue
        means = [float(by_key[(scheme, count)]["mean_ms"]) for count in COUNTS]
        stds = [float(by_key[(scheme, count)]["stddev_ms"]) for count in COUNTS]
        inset.errorbar(
            COUNTS,
            means,
            yerr=stds,
            color=COLORS[scheme],
            marker=MARKERS[scheme],
            linewidth=1.2 if scheme == "BAT-CLAMA" else 0.95,
            markersize=3.4,
            capsize=1.6,
            elinewidth=0.6,
        )
    inset.set_xticks(COUNTS)
    inset.set_ylim(0, low_range_max * 1.14)
    inset.grid(axis="y", linestyle="--", linewidth=0.35, alpha=0.28)
    inset.set_title("Zoom on Pairing-Free / Lightweight Schemes", fontsize=6.9, pad=2)
    inset.tick_params(labelsize=6.6)

    out_path = OUT_DIR / f"verification_time_{security_model}bit.png"
    fig.savefig(out_path, format="png")
    plt.close(fig)
    print(f"saved {out_path}")


def main():
    rows = read_rows()
    for security_model in SECURITY_MODELS:
        plot_for_security(rows, security_model)


if __name__ == "__main__":
    main()
