from dataclasses import dataclass
import zlib

M64 = (1 << 64) - 1

NEW, EST, CLOSED = 1, 2, 3
ALLOW, DROP = 1, 0

N = 1 << 16
T = 30_000_000
BUCKET_CHAIN_SIZE = 4

# Bucket chain statistics for hardware-native bucketed chaining analysis
_BUCKET_STATS = {
    "total_inserts": 0,
    "total_overflows": 0,
    "max_chain_depth": 0,
    "chain_depth_histogram": {i: 0 for i in range(BUCKET_CHAIN_SIZE + 1)},
}


@dataclass(frozen=True)
class Ev:
    sip: int
    sport: int
    dip: int
    dport: int
    proto: int
    inside: bool
    syn: bool
    ack: bool
    fin: bool
    rst: bool
    length: int
    ts: int


def canon(e):
    es = (e.sip << 16) | e.sport
    ed = (e.dip << 16) | e.dport

    a, b = (es, ed) if es <= ed else (ed, es)

    return (
        a >> 16,
        a & 0xFFFF,
        b >> 16,
        b & 0xFFFF,
        e.proto,
    )


def key_bytes(key):
    ia, pa, ib, pb, pr = key

    return (
        ia.to_bytes(4, "big")
        + pa.to_bytes(2, "big")
        + ib.to_bytes(4, "big")
        + pb.to_bytes(2, "big")
        + bytes([pr])
    )


def slot_of(key, n=N):
    return zlib.crc32(key_bytes(key)) % n


def step(tbl, e, n=N, t=T):
    key = canon(e)
    s = slot_of(key, n)
    chain = tbl.get(s, [])

    # Find matching key within the bucket chain.
    rec = None
    for k, st, last, pk, by in chain:
        if k == key:
            rec = (k, st, last, pk, by)
            break

    live = rec is not None and (e.ts - rec[2]) <= t

    init = e.inside and e.syn and not e.ack

    # Track bucket chain statistics
    _BUCKET_STATS["total_inserts"] += 1
    chain_depth = len(chain)
    if chain_depth < BUCKET_CHAIN_SIZE:
        _BUCKET_STATS["chain_depth_histogram"][chain_depth] = _BUCKET_STATS["chain_depth_histogram"].get(chain_depth, 0) + 1
    if chain_depth > _BUCKET_STATS["max_chain_depth"]:
        _BUCKET_STATS["max_chain_depth"] = chain_depth

    # Empty or expired (no live match in the chain).
    if not live:
        if init:
            if len(chain) < BUCKET_CHAIN_SIZE:
                chain.append((key, NEW, e.ts, 1, e.length))
                tbl[s] = chain
                _BUCKET_STATS["chain_depth_histogram"][chain_depth + 1] = _BUCKET_STATS["chain_depth_histogram"].get(chain_depth + 1, 0) + 1
                return ALLOW
            _BUCKET_STATS["total_overflows"] += 1
            return DROP  # bucket chain full
        return DROP

    k, st, last, pk, by = rec

    # Closed flow.
    if st == CLOSED:
        if init:
            chain = [
                (key, NEW, e.ts, 1, e.length) if k2 == k else (k2, st2, l2, p2, b2)
                for k2, st2, l2, p2, b2 in chain
            ]
            tbl[s] = chain
            return ALLOW
        return DROP

    npk = (pk + 1) & M64
    nby = (by + e.length) & M64

    # Connection termination.
    if e.rst or e.fin:
        chain = [
            (k, CLOSED, e.ts, npk, nby) if k2 == k else (k2, st2, l2, p2, b2)
            for k2, st2, l2, p2, b2 in chain
        ]
        tbl[s] = chain
        return ALLOW

    # NEW.
    if st == NEW:
        if e.inside:
            chain = [
                (k, NEW, e.ts, npk, nby) if k2 == k else (k2, st2, l2, p2, b2)
                for k2, st2, l2, p2, b2 in chain
            ]
            tbl[s] = chain
            return ALLOW

        if e.syn and e.ack:
            chain = [
                (k, EST, e.ts, npk, nby) if k2 == k else (k2, st2, l2, p2, b2)
                for k2, st2, l2, p2, b2 in chain
            ]
            tbl[s] = chain
            return ALLOW

        return DROP

    # EST.
    chain = [
        (k, EST, e.ts, npk, nby) if k2 == k else (k2, st2, l2, p2, b2)
        for k2, st2, l2, p2, b2 in chain
    ]
    tbl[s] = chain
    return ALLOW


def get_bucket_stats() -> dict:
    """Return bucket chain statistics for hardware-native bucketed chaining analysis."""
    stats = dict(_BUCKET_STATS)
    if stats["total_inserts"] > 0:
        stats["overflow_rate"] = stats["total_overflows"] / stats["total_inserts"]
    else:
        stats["overflow_rate"] = 0.0
    return stats


def reset_bucket_stats() -> None:
    """Reset bucket chain statistics."""
    global _BUCKET_STATS
    _BUCKET_STATS = {
        "total_inserts": 0,
        "total_overflows": 0,
        "max_chain_depth": 0,
        "chain_depth_histogram": {i: 0 for i in range(BUCKET_CHAIN_SIZE + 1)},
    }


def bucket_chain_overflow_probability(lam: float, chain_size: int = BUCKET_CHAIN_SIZE) -> float:
    """Calculate theoretical bucket chain overflow probability using Poisson distribution.

    P(overflow) = 1 - sum_{i=0}^{chain_size} e^{-lambda} * lambda^i / i!

    Where lambda = n_flows / N_slots is the average bucket load.
    """
    import math
    p_no_overflow = sum(
        math.exp(-lam) * lam ** i / math.factorial(i)
        for i in range(chain_size + 1)
    )
    return 1.0 - p_no_overflow
