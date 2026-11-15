"""Collision study (Fig. 6). Run from the root of the crossstate repo:
   python3 collision_study.py   (needs ref/model.py, numpy, matplotlib)"""
import random, sys
sys.path.insert(0, '.')
from ref.model import slot_of
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt, numpy as np
rng = random.Random(1); N = 65536
loads = [100, 500, 1000, 2000, 5000, 10000, 20000, 40000, 65536]
res = []
for n in loads:
    fr = []
    for t in range(30):
        seen = set(); rej = 0
        for _ in range(n):
            k = (rng.getrandbits(32), rng.randint(1024, 65535), rng.getrandbits(32), rng.choice([80, 443, 22, 53, 8080]), 6)
            a = (k[0] << 16 | k[1]); b = (k[2] << 16 | k[3])
            if a > b: k = (k[2], k[3], k[0], k[1], 6)   # canonical order
            s = slot_of(k)
            if s in seen: rej += 1
            else: seen.add(s)
        fr.append(rej / n * 100)
    res.append((n, np.mean(fr), np.std(fr))); print(n, round(np.mean(fr), 2), round(np.std(fr), 2))
x = [r[0] for r in res]; m = [r[1] for r in res]; s = [r[2] for r in res]
ana = [(1 - N * (1 - np.exp(-n / N)) / n) * 100 for n in x]
plt.figure(figsize=(4.2, 2.8), dpi=200)
plt.errorbar(x, m, yerr=s, fmt='o-', capsize=2, label='Measured (CRC32, 30 trials)')
plt.plot(x, ana, '--', label='Analytic (random hashing)')
plt.xscale('log'); plt.xlabel('Flows inserted'); plt.ylabel('Flows rejected by collision (%)')
plt.grid(alpha=.3); plt.legend(fontsize=7); plt.tight_layout(); plt.savefig('collision_load.png')
