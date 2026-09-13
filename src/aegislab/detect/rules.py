"""Detection rules.

DET-04 uses the canary engine (aegislab.canary) to attribute leaked
content back to its exact source document/record. Detection here never
phones home: it logs locally (stdlib `logging`) and appends to a local
JSONL file only.

Alerting and blocking are independent: DET-04 always alerts on a
verified canary hit, regardless of whether some other control (see
aegislab.defense.redact) also redacts the token from what the user
sees. Alert != block.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from aegislab.canary.detect import find_canaries

logger = logging.getLogger("aegislab.detect.rules")

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOG_PATH = _REPO_ROOT / "data" / "audit" / "detections.jsonl"


@dataclass(frozen=True)
class Detection:
    rule_id: str
    message: str
    attributed_source: str | None
    timestamp: str


def det_04_canary_leak(text: str, *, log_path: Path = DEFAULT_LOG_PATH) -> list[Detection]:
    """Scans text (model output, an email body, a tool result, ...) for
    canary tokens. Every verified hit is logged locally as DET-04, with
    attribution (tenant:doc_id) -- one JSONL line per hit, appended to
    log_path (default data/audit/detections.jsonl). Never sent anywhere.
    """
    detections = [
        Detection(
            rule_id="DET-04",
            message=f"canary token detected in output (tenant={hit.tenant}, doc_id={hit.doc_id})",
            attributed_source=f"{hit.tenant}:{hit.doc_id}",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        for hit in find_canaries(text)
    ]

    for detection in detections:
        logger.warning("DET-04 canary leak attributed to %s", detection.attributed_source)
        _append_jsonl(log_path, detection)

    return detections


def _append_jsonl(log_path: Path, detection: Detection) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(detection)) + "\n")
