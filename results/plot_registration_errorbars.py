#!/opt/homebrew/bin/python3.11
"""Generate publication-style error-bar figures for single-device signing time."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "registration.csv"
OUT_DIR = Path(__file__).resolve().parent
DPI = 600

matplotlib.rcParams.update(
    {
        "font.size": 10,
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "axes.labelsize": 10,
        "axes.titlesize": 11,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "legend.fontsize": 9,
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.04,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "mathtext.fontset": "stix",
    }
)

OURS = "BAT-CLAMA"
ORDER = [
    "BAT-CLAMA",
    "Cui-Edge-Batch",
    "PPT-CLAMA",
    "BMAE",
    "ECroA",
    "Shen-V2G",
   # "Ma-Edge-Update",
]
LABELS = {
    "BAT-CLAMA": "BAT-CLAMA",
    "Cui-Edge-Batch": "Cui et al.",
    "PPT-CLAMA": "PPT-CLAMA",
    "BMAE": "BMAE",
    "ECroA": "ECroA",
    "Shen-V2G": "Shen et al.",
   # "Ma-Edge-Update": "Ma et al.",
}
SECURITY_MODELS = ("80", "112", "128")
SECURITY_LABELS = {
    "80": "80-bit",
    "112": "112-bit",
    "128": "128-bit",
}
SECURITY_COLORS = {
    "80": "#4C78A8",
    "112": "#59A14F",
    "128": "#E17C05",
}


def read_rows() -> list[dict[str, str]]:
    with CSV_PATH.open() as handle:
        return list(csv.DictReader(handle))


def _draw_grouped_bars(ax, x, by_key, width, offsets):
    for security_model in SECURITY_MODELS:
        means = [float(by_key[(scheme, security_model)]["mean_ms"]) for scheme in ORDER]
        stds = [float(by_key[(scheme, security_model)]["stddev_ms"]) for scheme in ORDER]
        bars = ax.bar(
            [pos + offsets[security_model] for pos in x],
            means,
            width=width,
            yerr=stds,
            color=SECURITY_COLORS[security_model],
            edgecolor="black",
            linewidth=0.55,
            error_kw={"elinewidth": 0.75, "capsize": 1.8, "capthick": 0.75, "ecolor": "black"},
            label=SECURITY_LABELS[security_model],
            zorder=3,
        )
        if security_model == "128":
            for idx, bar in enumerate(bars):
                if ORDER[idx] == OURS:
                    bar.set_linewidth(1.0)


def plot_combined(rows: list[dict[str, str]]):
    by_key = {(row["scheme"], row["security_model"]): row for row in rows}
    labels = [LABELS[name] for name in ORDER]

    fig, (ax_top, ax_bottom) = plt.subplots(
        2,
        1,
        figsize=(3.55, 4.2),
        sharex=True,
        gridspec_kw={"height_ratios": [1.0, 2.4], "hspace": 0.05},
    )
    x = list(range(len(ORDER)))
    width = 0.18
    offsets = {"80": -width, "112": 0.0, "128": width}

    _draw_grouped_bars(ax_top, x, by_key, width, offsets)
    _draw_grouped_bars(ax_bottom, x, by_key, width, offsets)

    ax_top.set_ylim(170, 620)
    ax_bottom.set_ylim(0, 62)

    ax_top.spines["bottom"].set_visible(False)
    ax_bottom.spines["top"].set_visible(False)
    ax_top.tick_params(labeltop=False, bottom=False)
    ax_bottom.tick_params(top=False)

    d = 0.012
    kwargs = dict(transform=ax_top.transAxes, color="black", clip_on=False, linewidth=0.8)
    ax_top.plot((-d, +d), (-d, +d), **kwargs)
    ax_top.plot((1 - d, 1 + d), (-d, +d), **kwargs)
    kwargs = dict(transform=ax_bottom.transAxes, color="black", clip_on=False, linewidth=0.8)
    ax_bottom.plot((-d, +d), (1 - d, 1 + d), **kwargs)
    ax_bottom.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

    for axis in (ax_top, ax_bottom):
        axis.grid(axis="y", which="major", linestyle="--", linewidth=0.45, alpha=0.32, zorder=0)
        axis.axvspan(ORDER.index(OURS) - 0.42, ORDER.index(OURS) + 0.42, color="#F3E6D8", alpha=0.35, zorder=1)

    ax_bottom.set_xticks(x)
    ax_bottom.set_xticklabels(labels, rotation=26, ha="right")
    ax_bottom.set_ylabel("Mean Time (ms)")
    #ax_top.set_title("Single-Device Signing / Request Generation Time", pad=6)
    #ax_top.text(
     #   0.0,
     #   1.02,
     #   "Linear broken-axis view; error bars denote one standard deviation over 20 runs.",
     #   transform=ax_top.transAxes,
     #   ha="left",
      #  va="bottom",
      #  fontsize=8.5,
    #)
    ax_top.legend(loc="upper left", ncol=3, frameon=False, handlelength=1.3, columnspacing=0.9)

    out_path = OUT_DIR / "device_signing_time_combined_narrow.png"
    fig.savefig(out_path, format="png")
    plt.close(fig)
    print(f"saved {out_path}")


def main():
    rows = read_rows()
    plot_combined(rows)


if __name__ == "__main__":
    main()
