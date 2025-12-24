import math
import os

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for c in freq.values():
        p = c / len(data)
        ent -= p * math.log2(p)
    return ent


def ml_score(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(4096)

        e = entropy(data)
        size = os.path.getsize(path)

        # Heuristic ML-like decision
        if e > 7.5 and size < 5 * 1024 * 1024:
            return True

    except Exception:
        pass

    return False
