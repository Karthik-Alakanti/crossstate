#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${CROSSSTATE_ROOT:-$HOME/work/crossstate}"
if [[ ! -d "$ROOT" ]]; then
    ROOT="/home/karthik/work/crossstate"
fi
cd "$ROOT"

PY="$HOME/venvs/crossstate/bin/python"
VENV_SITE="$("$PY" -c 'import site; print(site.getsitepackages()[0])')"
export PYTHONPATH="$ROOT:$VENV_SITE"

BMV2_JSON="$ROOT/artifacts/state/firewall_g5_newflow_bmv2.json"
XDP_OBJ="$ROOT/artifacts/state/firewall_xdp_g5_newflow.o"

BMV2_SNAPSHOT="$ROOT/artifacts/state/g6_final_bmv2.json"
XDP_SNAPSHOT="$ROOT/artifacts/state/g6_final_xdp.json"

THRIFT=9090

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

fail() {
    echo
    echo "STARTUP FAILED: $1" >&2
    echo "No existing target state was deliberately reset." >&2
    exit 1
}

for file in "$BMV2_JSON" "$XDP_OBJ" "$BMV2_SNAPSHOT" "$XDP_SNAPSHOT"; do
    [[ -s "$file" ]] || fail "Missing or empty artifact: $file"
done

command -v ip >/dev/null || fail "ip command missing"
command -v bpftool >/dev/null || fail "bpftool missing"
command -v simple_switch_grpc >/dev/null || fail "simple_switch_grpc missing"

"$PY" -c 'from thrift import Thrift; import scapy.all; print("Python dependencies: PASS")'

sudo -v

bmv2_online() {
    sudo ss -lntp | grep -q ":$THRIFT"
}

xdp_online() {
    sudo bpftool net show 2>/dev/null | grep -Fq 'cs-xdp('
}

ensure_veth() {
    local left="$1"
    local right="$2"
    local left_mac="$3"
    local right_mac="$4"

    local have_left=0
    local have_right=0

    ip link show dev "$left" >/dev/null 2>&1 && have_left=1 || true
    ip link show dev "$right" >/dev/null 2>&1 && have_right=1 || true

    if (( ! have_left && ! have_right )); then
        echo "Creating veth: $left <-> $right"
        sudo ip link add "$left" type veth peer name "$right"
    elif (( ! have_left || ! have_right )); then
        fail "Incomplete veth pair: $left / $right. Inspect interfaces before recovery."
    else
        echo "Reusing veth: $left <-> $right"
    fi

    sudo ip link set dev "$left" address "$left_mac"
    sudo ip link set dev "$right" address "$right_mac"
    sudo ip link set dev "$left" up
    sudo ip link set dev "$right" up
}

verify_state() {
    section "VERIFYING RESTORED STATE"

    sudo env PYTHONPATH="$PYTHONPATH" "$PY" - <<'PY'
from pathlib import Path
from scripts import import_bmv2_state as bm
from scripts import import_xdp_state as xd
from scripts import sync_state

root = Path.cwd()
state = root / "artifacts/state"

bp = state / "startup_verify_bmv2.json"
xp = state / "startup_verify_xdp.json"
cp = state / "startup_verify_comparison.json"

b = sync_state.export_state("bmv2", bp, 9090)
x = sync_state.export_state("xdp", xp, 9090)
report = sync_state.compare(bp, xp, cp)

assert len(b["records"]) == 86, f"BMv2 has {len(b['records'])} records"
assert len(x["records"]) == 86, f"XDP has {len(x['records'])} records"
assert report["equivalent"], "BMv2/XDP state differs"

slots = sorted(r["slot"] for r in b["records"])
bm_state = bm.read_slots(slots, 9090)
map_id = xd.find_map_info()["id"]

for slot in slots:
    record = bm_state.get(slot)
    assert record is not None and record["synced"] == 1, \
        f"BMv2 slot {slot} is not ready"

    raw = xd.read_raw_slot(map_id, slot)
    assert raw[14] == 1 and raw[15] == 1, \
        f"XDP slot {slot} is not ready"

print("BMv2 records:", len(b["records"]))
print("XDP records:", len(x["records"]))
print("Exact matches:", len(report["exact_matches"]))
print("All BMv2 readiness flags: PASS")
print("All XDP readiness flags: PASS")
print("STARTUP_STATE_VERIFICATION = PASS")
PY
}

section "CROSSSTATE RUNTIME STARTUP"
echo "Repository: $ROOT"

BM=0
XD=0

bmv2_online && BM=1 || true
xdp_online && XD=1 || true

# Both online: preserve state and only validate.
if (( BM && XD )); then
    echo "Both dataplanes already running."
    verify_state
    echo
    echo "CROSSSTATE RUNTIME READY"
    exit 0
fi

# Partial runtime: never blindly recreate or replace a live target.
if (( BM || XD )); then
    fail "Partial runtime detected. BMv2=$BM XDP=$XD. Inspect before recovery."
fi

section "1. RECREATE VIRTUAL NETWORKS"

ensure_veth \
    cs-host cs-bmv2 \
    8a:e6:c2:1f:f7:28 \
    42:5d:f5:f9:83:48

ensure_veth \
    cs-xdp-host cs-xdp \
    8e:75:2c:70:10:b0 \
    76:57:a3:a7:6a:8e

section "2. ATTACH XDP"

if xdp_online; then
    echo "XDP already attached; preserving current map."
else
    sudo ip link set dev cs-xdp xdpdrv obj "$XDP_OBJ" sec xdp
fi

sudo bpftool net show
sudo bpftool map show | grep -A4 -B1 flow_state

section "3. START BMv2"

SWITCH_BIN="$(command -v simple_switch_grpc)"

sudo nohup "$SWITCH_BIN" \
    --device-id 1 \
    --thrift-port "$THRIFT" \
    -i 1@cs-bmv2 \
    "$BMV2_JSON" \
    >/tmp/crossstate-bmv2.log 2>&1 </dev/null &

echo "Waiting for BMv2 Thrift..."

READY=0
for i in $(seq 1 20); do
    if bmv2_online; then
        READY=1
        break
    fi
    sleep 0.5
done

if (( ! READY )); then
    tail -40 /tmp/crossstate-bmv2.log || true
    fail "BMv2 did not start on Thrift port $THRIFT"
fi

echo "BMv2 Thrift: READY"

section "4. RESTORE SAVED BMv2 STATE"

sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
    scripts/import_bmv2_state.py "$BMV2_SNAPSHOT" \
    --thrift-port "$THRIFT" --apply

section "5. RESTORE SAVED XDP STATE"

sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
    scripts/import_xdp_state.py "$XDP_SNAPSHOT" \
    --apply

section "6. RECONCILE READINESS"

sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
    scripts/sync_state.py \
    --direction bmv2-to-xdp \
    --apply --traffic-quiesced

sudo env PYTHONPATH="$PYTHONPATH" "$PY" \
    scripts/sync_state.py \
    --direction xdp-to-bmv2 \
    --apply --traffic-quiesced

section "7. FINAL STARTUP VERIFICATION"

verify_state

section "CROSSSTATE RUNTIME READY"

echo "BMv2: Running"
echo "Thrift: $THRIFT"
echo "XDP: Attached in native driver mode"
echo "Flow records: 86 on each target"
echo "Readiness: All verified"
echo
echo "NEXT COMMAND:"
echo "bash scripts/crossstate_master_demo.sh"
echo
echo "CROSSSTATE_STARTUP = PASS"
