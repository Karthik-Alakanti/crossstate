from dataclasses import dataclass
import zlib

M64 = (1 << 64) - 1

NEW, EST, CLOSED = 1, 2, 3
ALLOW, DROP = 1, 0

N = 1 << 16
T = 30_000_000


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
    rec = tbl.get(s)

    live = rec is not None and (e.ts - rec[2]) <= t

    init = e.inside and e.syn and not e.ack

    # Empty or expired
    if not live:
        if init:
            tbl[s] = (key, NEW, e.ts, 1, e.length)
            return ALLOW
        return DROP

    k, st, last, pk, by = rec

    # Live hash collision
    if k != key:
        return DROP

    # Closed flow
    if st == CLOSED:
        if init:
            tbl[s] = (key, NEW, e.ts, 1, e.length)
            return ALLOW
        return DROP

    npk = (pk + 1) & M64
    nby = (by + e.length) & M64

    # Connection termination
    if e.rst or e.fin:
        tbl[s] = (k, CLOSED, e.ts, npk, nby)
        return ALLOW

    # NEW
    if st == NEW:
        if e.inside:
            tbl[s] = (k, NEW, e.ts, npk, nby)
            return ALLOW

        if e.syn and e.ack:
            tbl[s] = (k, EST, e.ts, npk, nby)
            return ALLOW

        return DROP

    # EST
    tbl[s] = (k, EST, e.ts, npk, nby)
    return ALLOW
