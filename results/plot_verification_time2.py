#!/opt/homebrew/bin/python3.11
"""Plot device-registration runtime with error-bar line charts."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT     = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "device_registration_1.csv"
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

# ── Scheme definitions ────────────────────────────────────────────────────────
SCHEME_ORDER = [
    "BAT-CLAMA", "PPT-CLAMA", "BMAE",
    "Cui-Edge-Batch", "ECroA", "Shen-V2G",
]
LABELS = {
    "BAT-CLAMA":      "Ours",
    "PPT-CLAMA":      "PPT-CLAMA",
    "BMAE":           "BMAE",
    "Cui-Edge-Batch": "Cui et al.",
    # "Ma-Edge-Update": "Ma et al.",
    "ECroA":          "ECroA",
    "Shen-V2G":       "Shen et al.",
}

# Paul Tol "Bright" — colorblind-safe, consistent with bar-chart companion
COLORS = {
    "BAT-CLAMA":      "#EE6677",
    "PPT-CLAMA":      "#4477AA",
    "BMAE":           "#228833",
    "Cui-Edge-Batch": "#CCBB44",
    # "Ma-Edge-Update": "#AA3377",
    "ECroA":          "#66CCEE",
    "Shen-V2G":       "#BBBBBB",
}
LINESTYLES = {
    "BAT-CLAMA":      "-",
    "PPT-CLAMA":      "-",
    "BMAE":           "--",
    "Cui-Edge-Batch": "-.",
    # "Ma-Edge-Update": ":",
    "ECroA":          (0, (5, 1)),
    "Shen-V2G":       (0, (3, 1, 1, 1)),
}
MARKERS = {
    "BAT-CLAMA":      "o",
    "PPT-CLAMA":      "s",
    "BMAE":           "D",
    "Cui-Edge-Batch": "^",
    # "Ma-Edge-Update": "v",
    "ECroA":          "P",
    "Shen-V2G":       "X",
}

COUNTS          = [8, 16, 32, 64, 128]
SECURITY_MODELS = ["80", "112", "128"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def read_rows() -> list[dict[str, str]]:
    with CSV_PATH.open() as handle:
        return list(csv.DictReader(handle))


def _draw_line(
    ax,
    by_key: dict,
    scheme: str,
    *,
    inset: bool = False,
) -> tuple[list[float], list[float]]:
    """Draw one error-bar series onto *ax*; return (means, stds)."""
    means = [float(by_key[(scheme, c)]["mean_ms"])   for c in COUNTS]
    stds  = [float(by_key[(scheme, c)]["stddev_ms"]) for c in COUNTS]
    proposed = scheme in ("BAT-CLAMA", "PPT-CLAMA")

    if inset:
        lw, ms, elw, cap = (
            1.35 if proposed else 0.95,
            3.5  if proposed else 2.8,
            0.55, 1.5,
        )
    else:
        lw, ms, elw, cap = (
            1.85 if proposed else 1.20,
            5.5  if proposed else 4.0,
            0.80, 2.5,
        )

    ax.errorbar(
        COUNTS, means, yerr=stds,
        # Suppress inset labels so fig.legend() only collects main-axis handles
        label=LABELS[scheme] if not inset else "_nolegend_",
        color=COLORS[scheme],
        linestyle=LINESTYLES[scheme],
        marker=MARKERS[scheme],
        linewidth=lw,
        markersize=ms,
        capsize=cap,
        elinewidth=elw,
        capthick=elw,
        zorder=4 if proposed else 3,
        markeredgewidth=0.65 if proposed else 0.40,
        markeredgecolor="white" if proposed else COLORS[scheme],
    )
    return means, stds


def _style_inset_spines(ins_ax) -> None:
    """Restore all four spines with a thin, muted box border."""
    for sp in ins_ax.spines.values():
        sp.set_visible(True)
        sp.set_linewidth(0.55)
        sp.set_color("0.45")


# ── Main plot function ────────────────────────────────────────────────────────

def plot_for_security(rows: list[dict[str, str]], security_model: str) -> None:
    subset = [r for r in rows if r["security_model"] == security_model]
    by_key = {(r["scheme"], int(r["devices"])): r for r in subset}

    # Extra width accommodates the right-side legend without squeezing the plot
    fig, ax = plt.subplots(figsize=(7.4, 3.6))

    # ── Draw all series ───────────────────────────────────────────────────────
    max_y = low_range_max = 0.0
    for scheme in SCHEME_ORDER:
        means, stds = _draw_line(ax, by_key, scheme)
        top = max(m + s for m, s in zip(means, stds))
        max_y = max(max_y, top)
        if scheme != "Shen-V2G":
            low_range_max = max(low_range_max, top)

    # ── Main axes cosmetics ───────────────────────────────────────────────────
    ax.set_xlabel("Number of Devices", labelpad=4)
    ax.set_ylabel("Registration Time (ms)", labelpad=4)
    ax.set_xticks(COUNTS)
    ax.margins(x=0.06)
    ax.set_ylim(0, max_y * 1.10)

    ax.yaxis.grid(True, linestyle="--", linewidth=0.40, color="0.78", alpha=0.85, zorder=0)
    ax.xaxis.grid(True, linestyle=":",  linewidth=0.30, color="0.85", alpha=0.80, zorder=0)
    ax.set_axisbelow(True)

    # ── Inset (zoom): upper-left corner, in axes-fraction coordinates ─────────
    # [left, bottom, width, height] — all in axes fraction (0–1).
    # Sitting in the upper-left keeps it clear of the dense right-side curves
    # where Shen et al. dominates; the white facecolor occludes any background
    # grid lines from the main axes passing underneath.
    ins = ax.inset_axes([0.03, 0.52, 0.35, 0.44])
    ins.set_facecolor("white")

    for scheme in SCHEME_ORDER:
        if scheme == "Shen-V2G":
            continue
        _draw_line(ins, by_key, scheme, inset=True)

    ins.set_xticks(COUNTS)
    ins.margins(x=0.06)
    ins.set_ylim(0, low_range_max * 1.12)
    ins.yaxis.grid(True, linestyle="--", linewidth=0.30, color="0.78", alpha=0.85, zorder=0)
    ins.set_axisbelow(True)
    ins.set_title("Zoom (excl. Shen et al.)", fontsize=6.8, pad=3, fontweight="normal")
    ins.tick_params(
        axis="both", which="major",
        labelsize=6.5, direction="in", length=3.0, width=0.5,
    )
    _style_inset_spines(ins)

    # ── Legend: outside axes on the right (figure-fraction coordinates) ───────
    # Consistent with the companion bar-chart figure.
    # fig.legend() uses figure-fraction coordinates for bbox_to_anchor.
    # (1.01, 0.50) places the anchor just beyond the right edge of the figure,
    # vertically centred; loc="center left" anchors the legend box's left-centre
    # to that point. savefig.bbox="tight" automatically extends the canvas to
    # include the legend — no manual subplots_adjust required.
    # Handles are collected explicitly from ax to exclude inset "_nolegend_"
    # entries that would otherwise produce duplicates.
    handles, labs = ax.get_legend_handles_labels()
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
        handlelength=2.2,
        handletextpad=0.50,
        borderaxespad=0,
    )
    leg.get_frame().set_linewidth(0.5)

    # ── Save ─────────────────────────────────────────────────────────────────
    out_path = OUT_DIR / f"device_registration_{security_model}bit.png"
    fig.savefig(out_path, format="png")
    plt.close(fig)
    print(f"saved → {out_path}")


def main() -> None:
    rows = read_rows()
    for sm in SECURITY_MODELS:
        plot_for_security(rows, sm)


if __name__ == "__main__":
    main()