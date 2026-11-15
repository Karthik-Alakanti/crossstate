import random
import json

from ref.model import key_bytes, slot_of

random.seed(1)

out = []

for _ in range(20):
    k = (
        random.getrandbits(32),
        random.getrandbits(16),
        random.getrandbits(32),
        random.getrandbits(16),
        6,
    )

    out.append({
        "key": k,
        "bytes": key_bytes(k).hex(),
        "slot": slot_of(k),
    })

with open("artifacts/crc_vectors.json", "w") as f:
    json.dump(out, f, indent=1)

print("wrote 20 vectors")
