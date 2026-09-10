"""Tests for the eval harness (eval/run_all.py). Runs the real A01 attack
script as a subprocess with FakeLLM fixtures -- no live model, no network.
"""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUN_ALL_PATH = REPO_ROOT / "eval" / "run_all.py"


def _load_run_all():
    spec = importlib.util.spec_from_file_location("aegislab_eval_run_all", RUN_ALL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses needs the module registered before exec
    spec.loader.exec_module(module)
    return module


def test_discover_attacks_finds_a01():
    run_all = _load_run_all()
    discovered = run_all.discover_attacks()
    assert "A01_direct_injection" in {p.name for p in discovered}


def test_run_scenario_a01_broken_off_blocked_on():
    run_all = _load_run_all()
    attack_dir = run_all.ATTACKS_DIR / "A01_direct_injection"

    result = run_all.run_scenario(attack_dir)

    assert result.attack_dir == "A01_direct_injection"
    assert result.broken_off is True
    assert result.blocked_on is True
    assert result.residual is False


def test_missing_ids_lists_a02_through_a06():
    run_all = _load_run_all()
    discovered = run_all.discover_attacks()

    missing = run_all._missing_ids(discovered)

    assert missing == ["A02", "A03", "A04", "A05", "A06"]


def test_main_writes_scorecard_with_expected_table(tmp_path, monkeypatch):
    run_all = _load_run_all()
    report_path = tmp_path / "scorecard.md"
    monkeypatch.setattr(run_all, "REPORT_PATH", report_path)

    exit_code = run_all.main()

    assert exit_code == 0
    assert report_path.exists()

    content = report_path.read_text(encoding="utf-8")
    assert "| attack | broken_off | blocked_on | residual |" in content
    assert "A01_direct_injection" in content
    assert "Not yet implemented: A02, A03, A04, A05, A06." in content
