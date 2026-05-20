#!/opt/homebrew/bin/python3.11
"""Generate publication-style error-bar figures for single-device signing time."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT     = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "device_signing.csv"
OUT_DIR  = Path(__file__).resolve().parent
DPI      = 600

# ── Global typography & style ─────────────────────────────────────────────────
matplotlib.rcParams.update({
    "font.family":        "serif",
    "font.serif":         ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size":          9,
    "axes.labelsize":     9,
    "axes.titlesize":     9.5,
    "xtick.labelsize":    8,
    "ytick.labelsize":    8,
    "legend.fontsize":    7.5,
    "figure.dpi":         DPI,
    "savefig.dpi":        DPI,
    "savefig.bbox":       "tight",
    "savefig.pad_inches": 0.05,
    "axes.spines.top":    False,
    "axes.spines.right":  False,
    "axes.linewidth":     0.75,
    "xtick.direction":    "in",
    "ytick.direction":    "in",
    "xtick.major.size":   4.0,
    "ytick.major.size":   4.0,
    "xtick.major.width":  0.75,
    "ytick.major.width":  0.75,
    "xtick.minor.size":   2.5,
    "ytick.minor.size":   2.5,
    "xtick.minor.width":  0.5,
    "ytick.minor.width":  0.5,
    "mathtext.fontset":   "stix",
})

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
    "BAT-CLAMA":      "Ours",
    "Cui-Edge-Batch": "Cui et al.",
    "PPT-CLAMA":      "PPT-CLAMA",
    "BMAE":           "BMAE",
    "ECroA":          "ECroA",
    "Shen-V2G":       "Shen et al.",
    # "Ma-Edge-Update": "Ma et al.",
}
SECURITY_MODELS = ("80", "112", "128")
SECURITY_LABELS = {
    "80":  "80-bit",
    "112": "112-bit",
    "128": "128-bit",
}
# Paul Tol "Bright" — colorblind-safe, consistent with line-chart companion
SECURITY_COLORS = {
    "80":  "#4477AA",   # blue
    "112": "#228833",   # green
    "128": "#EE6677",   # red
}


def read_rows() -> list[dict[str, str]]:
    with CSV_PATH.open() as handle:
        return list(csv.DictReader(handle))


def _draw_grouped_bars(ax, x, by_key, width, offsets):
    for security_model in SECURITY_MODELS:
        means = [float(by_key[(scheme, security_model)]["mean_ms"])   for scheme in ORDER]
        stds  = [float(by_key[(scheme, security_model)]["stddev_ms"]) for scheme in ORDER]
        bars = ax.bar(
            [pos + offsets[security_model] for pos in x],
            means,
            width=width,
            yerr=stds,
            color=SECURITY_COLORS[security_model],
            edgecolor="white",          # thin white gap separates adjacent bars
            linewidth=0.55,
            error_kw={
                "elinewidth": 0.75,
                "capsize":    2.0,
                "capthick":   0.75,
                "ecolor":     "0.25",
            },
            label=SECURITY_LABELS[security_model],
            zorder=3,
            alpha=0.88,
        )
        # Emphasise our scheme in every security group
        if security_model == "128":
            for idx, bar in enumerate(bars):
                if ORDER[idx] == OURS:
                    bar.set_linewidth(1.2)
                    bar.set_edgecolor("0.20")


def plot_combined(rows: list[dict[str, str]]):
    by_key   = {(row["scheme"], row["security_model"]): row for row in rows}
    x_labels = [LABELS[name] for name in ORDER]

    # Extra width (4.2 vs original 3.55) gives the bar area room to breathe;
    # savefig.bbox="tight" automatically extends the canvas to include the
    # right-side legend without any manual subplots_adjust call.
    fig, (ax_top, ax_bottom) = plt.subplots(
        2, 1,
        figsize=(4.2, 4.2),
        sharex=True,
        gridspec_kw={"height_ratios": [1.0, 2.4], "hspace": 0.05},
    )
    x       = list(range(len(ORDER)))
    width   = 0.18
    offsets = {"80": -width, "112": 0.0, "128": width}

    _draw_grouped_bars(ax_top,    x, by_key, width, offsets)
    _draw_grouped_bars(ax_bottom, x, by_key, width, offsets)

    # ── Broken-axis y-limits ──────────────────────────────────────────────────
    ax_top.set_ylim(170, 620)
    ax_bottom.set_ylim(0, 62)

    # ── Spine / tick adjustments for broken axis ──────────────────────────────
    ax_top.spines["bottom"].set_visible(False)
    ax_bottom.spines["top"].set_visible(False)
    ax_top.tick_params(labeltop=False, bottom=False)
    ax_bottom.tick_params(top=False)

    # ── Diagonal break marks ──────────────────────────────────────────────────
    d = 0.012
    kwargs = dict(transform=ax_top.transAxes, color="black", clip_on=False, linewidth=0.8)
    ax_top.plot((-d, +d), (-d, +d), **kwargs)
    ax_top.plot((1 - d, 1 + d), (-d, +d), **kwargs)
    kwargs = dict(transform=ax_bottom.transAxes, color="black", clip_on=False, linewidth=0.8)
    ax_bottom.plot((-d, +d), (1 - d, 1 + d), **kwargs)
    ax_bottom.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

    # ── Grid & highlight band ─────────────────────────────────────────────────
    for axis in (ax_top, ax_bottom):
        axis.yaxis.grid(
            True, linestyle="--", linewidth=0.40,
            color="0.78", alpha=0.85, zorder=0,
        )
        axis.set_axisbelow(True)
        axis.axvspan(
            ORDER.index(OURS) - 0.42,
            ORDER.index(OURS) + 0.42,
            color="#F3E6D8", alpha=0.35, zorder=1,
        )

    # ── x-axis labels ─────────────────────────────────────────────────────────
    ax_bottom.set_xticks(x)
    ax_bottom.set_xticklabels(x_labels, rotation=26, ha="right")

    # ── y-axis label ──────────────────────────────────────────────────────────
    ax_bottom.set_ylabel("Signing Time (ms)", labelpad=4)

    # ── Legend: outside axes on the right, single column ─────────────────────
    # fig.legend() uses figure-fraction coordinates for bbox_to_anchor.
    # (1.01, 0.50) places the anchor just beyond the right edge, vertically
    # centred across the full figure height (both panels combined).
    # loc="center left" anchors the legend box's left-centre to that point.
    handles, labs = ax_top.get_legend_handles_labels()
    leg = fig.legend(
        handles, labs,
        ncol=1,
        frameon=True,
        framealpha=0.92,
        edgecolor="0.72",
        fancybox=False,           # square corners — formal publication style
        loc="center left",
        bbox_to_anchor=(1.01, 0.50),
        borderpad=0.75,
        labelspacing=0.50,
        handlelength=2.0,
        handletextpad=0.50,
        borderaxespad=0,
    )
    leg.get_frame().set_linewidth(0.5)

    out_path = OUT_DIR / "device_signing_time_combined_narrow.png"
    fig.savefig(out_path, format="png")
    plt.close(fig)
    print(f"saved {out_path}")


def main():
    rows = read_rows()
    plot_combined(rows)


if __name__ == "__main__":
    main()