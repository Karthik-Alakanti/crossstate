from hypothesis import given, strategies as st
from ref.model import *

C, S = (0x0A000001, 40000), (0x0A000002, 80)


def ev(
    inside,
    ts,
    syn=False,
    ack=False,
    fin=False,
    rst=False,
    ln=100,
):
    a, b = (C, S) if inside else (S, C)

    return Ev(
        a[0], a[1],
        b[0], b[1],
        6,
        inside,
        syn,
        ack,
        fin,
        rst,
        ln,
        ts,
    )


def test_handshake_and_expiry():
    t = {}

    assert step(t, ev(False, 1, ack=True)) == DROP
    assert step(t, ev(True, 2, syn=True)) == ALLOW
    assert step(t, ev(False, 3, syn=True, ack=True)) == ALLOW
    assert step(t, ev(True, 4)) == ALLOW
    assert step(t, ev(True, 5, fin=True)) == ALLOW
    assert step(t, ev(True, 6)) == DROP
    assert step(t, ev(True, 5 + T + 1)) == DROP
    assert step(t, ev(True, 5 + T + 2, syn=True)) == ALLOW


def test_bucket_chain_rejects_overflow():
    """More flows than BUCKET_CHAIN_SIZE hashing to same bucket are rejected."""
    t = {}

    base_ip = 0x0A000001
    # Find 5 distinct canonical keys that hash to the same slot.
    target_slot = None
    keys = []
    candidate = 1
    while len(keys) < BUCKET_CHAIN_SIZE + 1 and candidate < 0xFFFFFFFF:
        key = (candidate, 40000, candidate + 1, 40001, 6)
        s = slot_of(key)
        if target_slot is None:
            target_slot = s
        if s == target_slot:
            keys.append(key)
        candidate += 1

    if len(keys) < BUCKET_CHAIN_SIZE + 1:
        raise AssertionError("Could not find enough CRC bucket collisions.")

    ts = 1_000_000
    for i, key in enumerate(keys):
        e = Ev(
            key[0], key[1], key[2], key[3], 6,
            True, True, False, False, False,
            100, ts + i,
        )
        r = step(t, e)
        if i < BUCKET_CHAIN_SIZE:
            assert r == ALLOW, f"Chain insert {i} should be ALLOW"
        else:
            assert r == DROP, f"Chain overflow at {i} should be DROP"


@given(
    st.lists(
        st.tuples(
            st.booleans(),
            st.booleans(),
            st.booleans(),
            st.booleans(),
            st.booleans(),
        ),
        max_size=50,
    )
)
def test_never_crashes_and_ts_monotonic(flags):
    t = {}
    ts = 0

    for i, s, a, f, r in flags:
        ts += 1
        step(t, ev(i, ts, s, a, f, r), n=8)
