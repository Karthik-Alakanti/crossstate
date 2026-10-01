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
