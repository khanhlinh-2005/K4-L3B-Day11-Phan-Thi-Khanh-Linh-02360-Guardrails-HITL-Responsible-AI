from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogPlugin:
    """
    Audit log cho toàn bộ pipeline.

    Ghi:
        - user
        - input
        - output
        - blocked
        - layer
        - duration
        - timestamp
    """

    def __init__(self):
        self.records: list[dict[str, Any]] = []

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def record_input(
        self,
        user_id: str,
        input_text: str,
        **kwargs,
    ) -> dict:
        record = {
            "timestamp": self._timestamp(),
            "user_id": user_id,
            "input": input_text,
            "output": None,
            "blocked": False,
            "layer": None,
            "duration_ms": None,
        }

        record.update(kwargs)

        self.records.append(record)

        return record

    def record_output(
        self,
        *,
        user_id: str,
        input_text: str,
        output_text: str,
        blocked: bool = False,
        layer: str | None = None,
        duration_ms: float | None = None,
        **kwargs,
    ) -> dict:

        record = {
            "timestamp": self._timestamp(),
            "user_id": user_id,
            "input": input_text,
            "output": output_text,
            "blocked": blocked,
            "layer": layer,
            "duration_ms": duration_ms,
        }

        record.update(kwargs)

        self.records.append(record)

        return record

    def export_json(
        self,
        path: str | Path = "outputs/audit_log.json",
    ) -> None:

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.records,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def clear(self):
        self.records.clear()