"""Evaluation harness (LAB-ONLY).

Auto-discovers attacks/A0x_*/run.py scenarios, runs each twice as a
subprocess (--defense off, then --defense on), and writes
reports/scorecard.md summarizing which attacks the defense layer
actually blocks.

Every discovered attack script uses FakeLLM fixtures internally (see
attacks/A01_direct_injection/run.py) -- no live model, no network calls.
Scenarios A02-A06 are not implemented yet and are listed as such rather
than silently skipped.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACKS_DIR = REPO_ROOT / "attacks"
REPORT_PATH = REPO_ROOT / "reports" / "scorecard.md"

EXPECTED_IDS = [f"A{n:02d}" for n in range(1, 7)]  # A01..A06
_ID_RE = re.compile(r"^(A\d{2})_")


@dataclass
class ScenarioResult:
    attack_dir: str
    broken_off: bool
    blocked_on: bool
    residual: bool


def discover_attacks() -> list[Path]:
    """Attack scenario directories under attacks/ that have a run.py."""
    if not ATTACKS_DIR.exists():
        return []
    return [
        path
        for path in sorted(ATTACKS_DIR.iterdir())
        if path.is_dir() and _ID_RE.match(path.name) and (path / "run.py").exists()
    ]


def _run_once(run_py: Path, defense: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(run_py), "--defense", defense],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{run_py} --defense {defense} failed:\n{result.stderr}")

    evidence_path = run_py.parent / "evidence.json"
    return json.loads(evidence_path.read_text(encoding="utf-8"))


def run_scenario(attack_dir: Path) -> ScenarioResult:
    run_py = attack_dir / "run.py"

    evidence_off = _run_once(run_py, "off")
    evidence_on = _run_once(run_py, "on")

    broken_off = bool(evidence_off.get("leak_detected"))
    leak_on = bool(evidence_on.get("leak_detected"))

    return ScenarioResult(
        attack_dir=attack_dir.name,
        broken_off=broken_off,
        blocked_on=not leak_on,
        residual=leak_on,
    )


def _missing_ids(discovered: list[Path]) -> list[str]:
    found_ids = {_ID_RE.match(path.name).group(1) for path in discovered}
    return [attack_id for attack_id in EXPECTED_IDS if attack_id not in found_ids]


def render_scorecard(results: list[ScenarioResult], missing: list[str]) -> str:
    lines = [
        "# AegisLab Defense Scorecard",
        "",
        "LAB-ONLY. Each attack below is run twice against the intentionally",
        "weak baseline agent using FakeLLM fixtures: once with DEFENSE=off",
        "(the broken baseline) and once with DEFENSE=on (defense layer v1).",
        "",
        "| attack | broken_off | blocked_on | residual |",
        "| --- | --- | --- | --- |",
    ]

    if results:
        for r in results:
            lines.append(f"| {r.attack_dir} | {r.broken_off} | {r.blocked_on} | {r.residual} |")
    else:
        lines.append("| _(no attack scenarios discovered)_ | -- | -- | -- |")

    if missing:
        lines.append("")
        lines.append("Not yet implemented: " + ", ".join(missing) + ".")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    discovered = discover_attacks()
    results = [run_scenario(attack_dir) for attack_dir in discovered]
    missing = _missing_ids(discovered)

    scorecard = render_scorecard(results, missing)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(scorecard, encoding="utf-8")

    print(scorecard)
    print(f"Scorecard written to {REPORT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
