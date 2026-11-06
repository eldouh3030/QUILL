"""Figures of the paper from the CSV files in results/ (run from the repository root)."""
import csv, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

R = "results/"
O = sys.argv[1] if len(sys.argv) > 1 else "fig/"
os.makedirs(O, exist_ok=True)
INK = "#0b0b0b"; INK2 = "#52514e"; GRID = "#e4e3df"
C = {"ML-DSA-44": "#2a78d6", "Falcon-512": "#eb6834", "LMS (HSS L2 H10 W4)": "#1f9e6e",
     "SPHINCS+-SHA2-128s": "#8a5cc2", "SPHINCS+-SHA2-128f": "#c2408f", "Ed25519": "#8c8b85"}
SHORT = {"ML-DSA-44": "ML-DSA-44", "Falcon-512": "Falcon-512", "LMS (HSS L2 H10 W4)": "LMS/HSS",
         "SPHINCS+-SHA2-128s": "SPHINCS+-128s", "SPHINCS+-SHA2-128f": "SPHINCS+-128f", "Ed25519": "Ed25519 (classical)"}
MK = {"ML-DSA-44": "o", "Falcon-512": "s", "LMS (HSS L2 H10 W4)": "^", "SPHINCS+-SHA2-128s": "D",
      "SPHINCS+-SHA2-128f": "v", "Ed25519": "x"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
    "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True, "savefig.dpi": 300, "savefig.bbox": "tight",
    "legend.frameon": False})
rd = lambda f: list(csv.DictReader(open(R + f)))
F = lambda x: float(x)

# ------------------------------------------------------------ Fig. 1 overview
def box(ax, x, y, w, h, text, fc="#ffffff", ec=INK2, fs=8, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=0.9))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK, fontweight="bold" if bold else None)
def arrow(ax, x1, y1, x2, y2, col=INK2, ls="-", lw=1.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=9, color=col, lw=lw, linestyle=ls))

fig, ax = plt.subplots(figsize=(7.4, 5.6)); ax.set_xlim(0, 14.4); ax.set_ylim(0, 11.0); ax.axis("off")
BL, OR, GR, RED = "#2a78d6", "#eb6834", "#1f9e6e", "#c0392b"
def cross(x, y, w, h):
    ax.plot([x, x + w], [y, y + h], color=RED, lw=1.3); ax.plot([x, x + w], [y + h, y], color=RED, lw=1.3)
def tag(x, y, t, fs=8):
    ax.text(x, y, t, fontsize=fs, color=INK, fontweight="bold", va="center")
# (a) parties
tag(0.1, 10.75, "(a) Parties")
box(ax, 0.2, 8.85, 3.0, 1.5, "Wearable device D\nCortex-M4 + BLE\nsigning key $sk_D$", "#eef4fc", fs=7.5)
box(ax, 5.7, 8.85, 3.0, 1.5, "Gateway G\nML-KEM-512 and\nX25519 keys", "#fdf0ea", fs=7.5)
box(ax, 11.2, 8.85, 3.0, 1.5, "Auditor A\n(EHR, insurer, court)\nknows only $pk_D$", "#eef7f1", fs=7.5)
arrow(ax, 3.25, 10.0, 5.65, 10.0); ax.text(4.45, 10.13, "INIT (hybrid KEM)", ha="center", fontsize=6.3, color=INK2)
arrow(ax, 3.25, 9.4, 5.65, 9.4); ax.text(4.45, 9.53, "DATA frames, lossy", ha="center", fontsize=6.3, color=INK2)
arrow(ax, 5.65, 9.05, 3.25, 9.05, col=GR, ls="--", lw=0.8); ax.text(4.45, 8.65, "FEEDBACK (adaptive m, k)", ha="center", fontsize=6.3, color=GR)
arrow(ax, 8.75, 9.6, 11.15, 9.6); ax.text(9.95, 9.75, "record + evidence", ha="center", fontsize=6.3, color=INK2)
ax.text(9.95, 9.25, r"(+ $k_{b,i}$ to open)", ha="center", fontsize=6.3, color=INK2)
# (b) device
tag(0.1, 8.0, "(b) Device: batch b is signed; its authenticator rides inside batch b+1")
y0 = 5.3; w = 0.66; g = 0.74; top = y0 + 0.75
for j in range(8):
    x = 0.2 + j * g
    ax.add_patch(Rectangle((x, y0), w, 0.75, fc="#eef4fc", ec=BL, lw=0.8))
    ax.text(x + w / 2, y0 + 0.37, f"$c_{j+1}$", ha="center", va="center", fontsize=7.5)
for j in (2, 5): cross(0.2 + j * g, y0, w, 0.75)
ax.text(3.1, y0 - 0.32, r"GCM under $k_{b,i}$;  $L_i = H(0, b, i, th, KC_i, c_i)$", ha="center", fontsize=6.3, color=INK2)
lv = [(0.2 + j * g + w / 2, top) for j in range(8)]
for yy in (6.5, 6.95, 7.35):
    nx = []
    for i in range(len(lv) // 2):
        (x1, y1), (x2, y2) = lv[2 * i], lv[2 * i + 1]; xm = (x1 + x2) / 2
        ax.plot([x1, xm], [y1, yy], color=INK2, lw=0.6); ax.plot([x2, xm], [y2, yy], color=INK2, lw=0.6)
        ax.plot([xm], [yy], "o", ms=2.2, color=INK2); nx.append((xm, yy))
    lv = nx
ax.text(lv[0][0] + 0.15, 7.42, r"$R_b$", fontsize=7.5, va="center")
box(ax, 6.25, 6.6, 2.05, 0.6, r"$\sigma_b=\mathrm{Sign}(sk_D, R_b)$", "#ffffff", fs=6.3)
box(ax, 6.25, 5.45, 2.05, 0.7, "$m$ parity symbols\n$P$ of the leaves", "#ffffff", fs=6.3)
arrow(ax, lv[0][0] + 0.55, 7.35, 6.2, 6.95)
arrow(ax, 6.07, 5.8, 6.22, 5.8)
box(ax, 8.62, 5.95, 1.65, 0.8, r"$D_b=\sigma_b\,\|\,P$" + "\n" + r"$\to n$ fragments", "#fde3d6", ec=OR, fs=6.3)
arrow(ax, 8.33, 6.85, 8.6, 6.55); arrow(ax, 8.33, 5.85, 8.6, 6.15)
xb = 10.75
for j in range(4):
    x = xb + j * g
    ax.add_patch(Rectangle((x, y0), w, 0.75, fc="#eef4fc", ec=BL, lw=0.8))
    ax.add_patch(Rectangle((x, y0 + 0.48), w, 0.27, fc="#fde3d6", ec=OR, lw=0.6))
    ax.text(x + w / 2, y0 + 0.615, f"$f_{j+1}$", ha="center", va="center", fontsize=6)
    ax.text(x + w / 2, y0 + 0.23, f"$c_{j+1}$", ha="center", va="center", fontsize=7)
ax.text(xb + 4 * g + 0.02, y0 + 0.37, "...", fontsize=8, va="center")
cross(xb + 3 * g, y0, w, 0.75)
arrow(ax, 10.3, 6.35, 10.85, y0 + 0.8, col=OR)
ax.text(xb + 1.6, y0 - 0.32, r"batch b+1: any $k$ of $n$ rebuild $D_b$", ha="center", fontsize=6.3, color=INK2)
# (c) gateway pipeline
tag(0.1, 4.35, "(c) Gateway")
steps = [("decrypt and check\neach packet at once", "#fdf0ea"), ("hash the received\npackets into leaves", "#fdf0ea"),
         ("rebuild $D_b$ from\nany $k$ fragments", "#fde3d6"), ("recover up to $m$\nlost leaves from $P$", "#fde3d6"),
         ("recompute $R_b$\nand verify $\\sigma_b$", "#eef7f1")]
for t, (txt, fc) in enumerate(steps):
    x = 0.2 + t * 2.88
    box(ax, x, 2.95, 2.45, 1.0, txt, fc, fs=6.8)
    if t: arrow(ax, x - 0.42, 3.45, x - 0.03, 3.45)
ax.text(1.42, 2.62, "reading usable at once (G1)", ha="center", fontsize=6.3, color=INK2)
ax.text(12.94, 2.62, "received packets of b are\nnon-repudiable (G2)", ha="center", va="top", fontsize=6.3, color=INK2)
# (d) evidence
tag(0.1, 1.75, "(d) Evidence for one record and its opening")
box(ax, 0.2, 0.2, 8.4, 1.15, r"hdr, $c_{b,i}$, $KC_{b,i}$, Merkle path ($\lceil\log_2 n\rceil$ hashes), $\sigma_b$ (shared by the batch)"
    + "\n" + r"check: leaf $\to$ path $\to R_b$, then Verify$(pk_D, \sigma_b)$", "#ffffff", fs=6.6)
box(ax, 8.9, 0.2, 5.3, 1.15, r"open: G reveals $k_{b,i}$; A checks $H(k_{b,i}) = KC_{b,i}$" + "\nand decrypts: exactly one reading", "#eef7f1", fs=6.6)
fig.savefig(O + "fig-overview.png"); plt.close(fig)

# ------------------------------------------- Fig. 2 signing cost and size on the device
mcu = {r["function"]: r for r in rd("mcu-emulated.csv")}
comp = {r["function"]: r for r in rd("mcu-components.csv")}
sigs = [("Ed25519", "op_sign_ed25519", 64), ("ML-DSA-44", "op_sign_mldsa44", 2420), ("LMS (HSS L2 H10 W4)", "op_sign_lms", 5076),
        ("Falcon-512", "op_sign_falcon512", 666), ("SPHINCS+-SHA2-128f", "op_sign_sphincs128f", 17088),
        ("SPHINCS+-SHA2-128s", "op_sign_sphincs128s", 7856)]
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.7))
ms = [F((comp.get(f) or mcu[f])["cycles"]) / 64e3 for _, f, _ in sigs]
y = range(len(sigs))
ax[0].barh(y, ms, color=[C[s] for s, _, _ in sigs], height=0.62); ax[0].set_xscale("log"); ax[0].invert_yaxis()
ax[0].set_yticks(list(y)); ax[0].set_yticklabels([SHORT[s] for s, _, _ in sigs]); ax[0].grid(axis="y", visible=False)
for i, v in enumerate(ms): ax[0].text(v * 1.15, i, f"{v:,.0f} ms" if v >= 10 else f"{v:.1f} ms", va="center", fontsize=7.5)
ax[0].set_xlim(5, 1e6); ax[0].set_xlabel("signing time at 64 MHz (ms, log scale)")
ax[0].set_title("(a) One signature on the device", fontsize=9, loc="left")
sz = [b for _, _, b in sigs]
ax[1].barh(y, sz, color=[C[s] for s, _, _ in sigs], height=0.62); ax[1].set_xscale("log"); ax[1].invert_yaxis()
ax[1].set_yticks(list(y)); ax[1].set_yticklabels([]); ax[1].grid(axis="y", visible=False)
ax[1].axvline(244, color="#c0392b", lw=1, ls="--"); ax[1].text(260, 5.45, "one BLE\nframe (244 B)", fontsize=7, color="#c0392b")
for i, v in enumerate(sz): ax[1].text(v * 1.15, i, f"{v:,} B", va="center", fontsize=7.5)
ax[1].set_xlim(30, 2e5); ax[1].set_xlabel("signature size (bytes, log scale)")
ax[1].set_title("(b) Signature size", fontsize=9, loc="left")
fig.tight_layout(); fig.savefig(O + "fig-signatures.png"); plt.close(fig)

# --------------------------------- Fig. 3 overhead per packet vs loss (tuned m, k)
opt = rd("optimise-16.csv")
show = ["ML-DSA-44", "Falcon-512", "LMS (HSS L2 H10 W4)", "SPHINCS+-SHA2-128s", "Ed25519"]
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.8), sharey=True)
for a, burst, title in [(ax[0], "1", "(a) Independent losses"), (ax[1], "4", "(b) Bursty losses (mean burst 4)")]:
    for s in show:
        pts = [(F(r["loss"]) * 100, F(r["air_overhead_per_packet"])) for r in opt
               if r["signature"] == s and r["n"] == "32" and (r["burst"] == burst or r["loss"] == "0.00") and F(r["air_overhead_per_packet"]) > 0]
        pts.sort()
        a.plot([p for p, _ in pts], [o for _, o in pts], marker=MK[s], ms=4, lw=1.6, color=C[s], label=SHORT[s])
    a.set_xlabel("average packet loss (%)"); a.set_title(title, fontsize=9, loc="left")
ax[0].set_ylabel("air bytes added per packet")
ax[0].legend(fontsize=7, loc="upper left")
fig.tight_layout(); fig.savefig(O + "fig-overhead-loss.png"); plt.close(fig)

# ------------------------------------------- Fig. 4 batch size trade-off
fig, ax = plt.subplots(figsize=(4.6, 2.8))
for s in show:
    pts = [(int(r["n"]), F(r["air_overhead_per_packet"])) for r in opt
           if r["signature"] == s and r["loss"] == "0.05" and r["burst"] == "4" and F(r["air_overhead_per_packet"]) > 0]
    pts.sort()
    ax.plot([n for n, _ in pts], [o for _, o in pts], marker=MK[s], ms=4, lw=1.6, color=C[s], label=SHORT[s])
ax.set_xscale("log", base=2); ax.set_xticks([16, 32, 64, 128]); ax.set_xticklabels(["16", "32", "64", "128"])
ax.set_xlabel("batch size n (packets per signature)"); ax.set_ylabel("air bytes added per packet")
ax.set_title("5 % loss, mean burst 4, target 0.99", fontsize=9, loc="left"); ax.legend(fontsize=7)
fig.tight_layout(); fig.savefig(O + "fig-batch-size.png"); plt.close(fig)

# --------------------------------------------- Fig. 5 comparison with baselines
cmp_ = rd("compare-16.csv")
order = ["Proposed (m and k tuned)", "Proposed (fixed m and k)", "Leaf list coded (SAIDA-style)", "EMSS (2 links; signature x2)",
         "Batch signature x2", "Batch signature x1", "Sign each packet"]
CS = {"Proposed (m and k tuned)": "#2a78d6", "Proposed (fixed m and k)": "#7fb0ea", "Leaf list coded (SAIDA-style)": "#1f9e6e",
      "EMSS (2 links; signature x2)": "#8a5cc2", "Batch signature x2": "#eb6834", "Batch signature x1": "#f2a27f", "Sign each packet": "#8c8b85"}
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
for a, burst, title in [(ax[0], "1", "(a) Independent losses"), (ax[1], "4", "(b) Bursty losses (mean burst 4)")]:
    for sc in order:
        pts = sorted((F(r["loss"]) * 100, F(r["verified_of_sent"])) for r in cmp_
                     if r["scheme"] == sc and r["signature"] == "ML-DSA-44" and (r["burst"] == burst or r["loss"] == "0.00"))
        a.plot([p for p, _ in pts], [v for _, v in pts], marker="o", ms=3, lw=1.5, color=CS[sc], label=sc)
    a.set_xlabel("average packet loss (%)"); a.set_title(title, fontsize=9, loc="left"); a.set_ylim(-0.02, 1.02)
ax[0].set_ylabel("packets non-repudiable / sent")
h, l = ax[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=4, fontsize=7, bbox_to_anchor=(0.5, -0.08))
fig.tight_layout(rect=(0, 0.08, 1, 1)); fig.savefig(O + "fig-baselines.png"); plt.close(fig)

# ------------------------------------------------ Fig. 6 model validation
val = rd("validate.csv")
fig, ax = plt.subplots(figsize=(3.4, 3.0))
for cfg, col in [(("16", "4", "12"), "#2a78d6"), (("32", "8", "24"), "#eb6834")]:
    pts = [(F(r["model_ok"]), F(r["measured_ok"])) for r in val if (r["n"], r["m"], r["k"]) == cfg]
    ax.scatter([p for p, _ in pts], [q for _, q in pts], s=22, color=col, label=f"n={cfg[0]}, m={cfg[1]}, k={cfg[2]}", zorder=3)
ax.plot([0, 1], [0, 1], color=INK2, lw=0.8, ls="--")
ax.set_xlabel("model: P(batch verifiable)"); ax.set_ylabel("implementation: fraction verified")
ax.set_xlim(-0.02, 1.02); ax.set_ylim(-0.02, 1.02); ax.legend(fontsize=7, loc="upper left")
fig.tight_layout(); fig.savefig(O + "fig-validation.png"); plt.close(fig)

# ------------------------------------------------ Fig. 7 energy of the real streams
st = [r for r in rd("streams.csv") if r["loss"] == "0.05"]
fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.7))
for a, wl, title in [(ax[0], "Vitals", "(a) Vital signs, 1 record/s, n = 32"), (ax[1], "ECG", "(b) ECG, 5.6 packets/s, n = 64")]:
    rows = [r for r in st if r["workload"] == wl]
    rows.sort(key=lambda r: F(r["total_mJ_per_h"]))
    y = range(len(rows))
    cpu = [F(r["cpu_mJ_per_h"]) / 1000 for r in rows]; rad = [F(r["radio_mJ_per_h"]) / 1000 for r in rows]
    a.barh(y, cpu, color="#2a78d6", height=0.6, label="CPU")
    a.barh(y, rad, left=cpu, color="#eb6834", height=0.6, label="radio")
    a.set_yticks(list(y)); a.set_yticklabels([SHORT[r["signature"]] for r in rows]); a.grid(axis="y", visible=False)
    a.set_xscale("log"); a.set_xlabel("energy (J per hour, log scale)"); a.set_title(title, fontsize=9, loc="left")
    for i, r in enumerate(rows): a.text((cpu[i] + rad[i]) * 1.15, i, f"{F(r['total_mJ_per_h']) / 1000:.2f}", va="center", fontsize=7.5)
    a.set_xlim(0.03, 80)
ax[0].legend(fontsize=7, loc="lower right")
fig.tight_layout(); fig.savefig(O + "fig-energy.png"); plt.close(fig)
print("figures written to", O)
