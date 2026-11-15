from dataclasses import dataclass
import zlib

M64 = (1 << 64) - 1

NEW, EST, CLOSED = 1, 2, 3
ALLOW, DROP = 1, 0

N = 1 << 16
T = 30_000_000
BUCKET_CHAIN_SIZE = 4


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

    # Empty or expired (no live match in the chain).
    if not live:
        if init:
            if len(chain) < BUCKET_CHAIN_SIZE:
                chain.append((key, NEW, e.ts, 1, e.length))
                tbl[s] = chain
                return ALLOW
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
