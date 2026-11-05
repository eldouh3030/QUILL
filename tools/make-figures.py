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

fig, ax = plt.subplots(figsize=(7.2, 4.0)); ax.set_xlim(0, 14); ax.set_ylim(0, 8.0); ax.axis("off")
box(ax, 0.2, 5.6, 2.6, 1.8, "Wearable sensor\n(Cortex-M4, BLE)\nsigning key sk_D", "#eef4fc", bold=False)
box(ax, 5.6, 5.6, 2.8, 1.8, "Gateway / hospital\nedge (ML-KEM +\nX25519 keys)", "#fdf0ea")
box(ax, 11.0, 5.6, 2.8, 1.8, "EHR archive,\nauditor or court\n(device public key)", "#eef7f1")
arrow(ax, 2.85, 6.9, 5.55, 6.9); ax.text(4.2, 7.05, "INIT: KEM ct + signature", ha="center", fontsize=6.5, color=INK2)
arrow(ax, 2.85, 6.0, 5.55, 6.0); ax.text(4.2, 6.15, "DATA frames (lossy)", ha="center", fontsize=6.5, color=INK2)
arrow(ax, 8.45, 6.5, 10.95, 6.5); ax.text(9.7, 6.7, "record + evidence", ha="center", fontsize=6.5, color=INK2)
ax.text(9.7, 6.05, "(+ one packet key)", ha="center", fontsize=6.5, color=INK2)
# timeline of two batches
y0 = 3.6; ax.text(0.2, y0 + 1.25, "Batch b", fontsize=8, color=INK, fontweight="bold")
ax.text(7.2, y0 + 1.25, "Batch b+1", fontsize=8, color=INK, fontweight="bold")
for j in range(8):
    x = 0.2 + j * 0.82
    ax.add_patch(Rectangle((x, y0), 0.72, 0.9, fc="#eef4fc", ec="#2a78d6", lw=0.8))
    ax.text(x + 0.36, y0 + 0.45, f"c{j+1}", ha="center", va="center", fontsize=7)
for j in range(8):
    x = 7.2 + j * 0.82
    ax.add_patch(Rectangle((x, y0), 0.72, 0.9, fc="#eef4fc", ec="#2a78d6", lw=0.8))
    ax.add_patch(Rectangle((x, y0 + 0.6), 0.72, 0.3, fc="#fde3d6", ec="#eb6834", lw=0.6))
    ax.text(x + 0.36, y0 + 0.75, f"f{j+1}", ha="center", va="center", fontsize=6)
    ax.text(x + 0.36, y0 + 0.3, f"c{j+1}", ha="center", va="center", fontsize=7)
for j in (2, 5):   # lost packets
    x = 0.2 + j * 0.82; ax.plot([x, x + 0.72], [y0, y0 + 0.9], color="#c0392b", lw=1.2); ax.plot([x, x + 0.72], [y0 + 0.9, y0], color="#c0392b", lw=1.2)
x = 7.2 + 4 * 0.82; ax.plot([x, x + 0.72], [y0, y0 + 0.9], color="#c0392b", lw=1.2); ax.plot([x, x + 0.72], [y0 + 0.9, y0], color="#c0392b", lw=1.2)
ax.text(3.45, y0 - 0.4, "leaf_i = H(th, b, i, KC_i, c_i); R_b = Merkle root", ha="center", fontsize=6.5, color=INK2)
ax.text(3.45, y0 - 0.8, "sigma_b = Sign(sk_D, th, b, n, R_b)", ha="center", fontsize=6.5, color=INK2)
ax.text(10.45, y0 - 0.4, "D_b = sigma_b || m parity leaves -> n fragments", ha="center", fontsize=6.5, color=INK2)
ax.text(10.45, y0 - 0.8, "f_j encrypted with packet j; any k rebuild D_b", ha="center", fontsize=6.5, color=INK2)
arrow(ax, 6.8, y0 + 0.45, 7.15, y0 + 0.45, col="#eb6834")
ax.text(0.2, 1.75, "Gateway:", fontsize=8, fontweight="bold", color=INK)
ax.text(1.75, 1.75, "each c_i is decrypted and authenticated at once (per-packet AES-256-GCM key, no added delay);",
        fontsize=7.5, color=INK2)
ax.text(1.75, 1.25, "after k fragments of batch b+1 it rebuilds D_b, recovers up to m missing leaves from the parity,",
        fontsize=7.5, color=INK2)
ax.text(1.75, 0.75, "recomputes R_b and verifies sigma_b: every received packet of batch b becomes non-repudiable.",
        fontsize=7.5, color=INK2)
ax.text(0.2, 0.2, "Lost packets are crossed out. Keys: CK_b+1 = HKDF(CK_b), K_b = HKDF(CK_b), k_b,i = HKDF(K_b, i), KC_b,i = H(k_b,i).",
        fontsize=7, color=INK2)
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
