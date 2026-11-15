import pytest

from scripts import sync_state


def test_preflight_allows_source_only_slots():
    result = sync_state.validate_preflight({
        "left_only_slots": [100],
        "right_only_slots": [],
        "slot_conflicts": [],
    })
    assert result == []


def test_preflight_rejects_destination_only_slots():
    with pytest.raises(RuntimeError, match="Destination contains records"):
        sync_state.validate_preflight({
            "left_only_slots": [],
            "right_only_slots": [200],
            "slot_conflicts": [],
        })


def test_preflight_rejects_slot_conflicts():
    with pytest.raises(RuntimeError, match="Same-slot different-key conflicts"):
        sync_state.validate_preflight({
            "left_only_slots": [],
            "right_only_slots": [],
            "slot_conflicts": [{"slot": 300}],
        })


def test_source_stability_passes_when_unchanged(monkeypatch, tmp_path):
    calls = []

    def fake_export(target, output, thrift_port):
        calls.append((target, output, thrift_port))

    def fake_compare(left, right, report):
        return {"equivalent": True}

    monkeypatch.setattr(sync_state, "export_state", fake_export)
    monkeypatch.setattr(sync_state, "compare", fake_compare)

    result = sync_state.verify_source_stability(
        "bmv2",
        tmp_path / "initial.json",
        tmp_path / "after.json",
        tmp_path / "stability.json",
        9090,
    )

    assert result["equivalent"] is True
    assert calls[0][0] == "bmv2"
    assert calls[0][2] == 9090


def test_source_stability_rejects_changed_source(monkeypatch, tmp_path):
    monkeypatch.setattr(sync_state, "export_state", lambda *args: None)
    monkeypatch.setattr(
        sync_state, "compare", lambda *args: {"equivalent": False}
    )

    with pytest.raises(RuntimeError, match="source changed"):
        sync_state.verify_source_stability(
            "xdp",
            tmp_path / "initial.json",
            tmp_path / "after.json",
            tmp_path / "stability.json",
            9090,
        )


def test_fail_closed_attempts_to_clear_readiness(monkeypatch):
    calls = []

    monkeypatch.setattr(
        sync_state,
        "set_ready",
        lambda *args: calls.append(args),
    )

    sync_state.fail_closed("xdp", [10, 20], 9090)

    assert calls == [("xdp", [10, 20], False, 9090)]


def test_fail_closed_reports_readiness_failure(monkeypatch, capsys):
    def fail(*args):
        raise RuntimeError("simulated target failure")

    monkeypatch.setattr(sync_state, "set_ready", fail)
    sync_state.fail_closed("bmv2", [10], 9090)

    output = capsys.readouterr().out
    assert "FAIL_CLOSED_READINESS = ERROR" in output
    assert "simulated target failure" in output
