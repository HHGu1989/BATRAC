# BATRAC
a registration-secure certificateless mutual authentication and key agreement scheme

# Notes
1. This is an analytical simulation, not a complete network execution
   benchmark.
2. `scalar_mults` is a normalized effective operation count for horizontal
   comparison. It is not an instruction-level CPU cost.
3. Some newly added local implementation schemes, such as `BMAE` and
   `PSK-BAT-CLAMA`, use approximate operation counts derived from the current
   implementation path and protocol formulas.
4. For wall-clock measurements under the real threaded model, use the threaded
   demo scripts instead of [`simulate.py`](./simulate.py).
