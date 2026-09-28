from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class MonitoringAlert:
    """
    Monitoring metrics cho assignment.

    Metrics:
        total_requests
        blocked_requests
        rate_limited_requests
    """

    def __init__(
        self,
        block_warning_threshold: int = 5,
        rate_limit_warning_threshold: int = 3,
    ):
        self.total_requests = 0
        self.blocked_requests = 0
        self.rate_limited_requests = 0

        self.block_warning_threshold = block_warning_threshold
        self.rate_limit_warning_threshold = (
            rate_limit_warning_threshold
        )

        self.alerts: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    def record_request(self):
        self.total_requests += 1

    def record_block(self, layer: str | None = None):
        self.blocked_requests += 1

        if layer == "rate_limit":
            self.rate_limited_requests += 1

    def record_rate_limit(self):
        self.rate_limited_requests += 1
        self.blocked_requests += 1

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    def get_metrics(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "alerts": self.alerts,
        }

    # --------------------------------------------------------
    # Alert check
    # --------------------------------------------------------

    def check_metrics(self) -> list[dict]:
        """
        Kiểm tra threshold và tạo alert.
        """

        self.alerts = []

        if (
            self.blocked_requests
            >= self.block_warning_threshold
        ):
            self.alerts.append(
                {
                    "type": "blocked_requests",
                    "severity": "warning",
                    "message": (
                        "Blocked request count exceeded "
                        "warning threshold."
                    ),
                    "value": self.blocked_requests,
                    "threshold": (
                        self.block_warning_threshold
                    ),
                }
            )

        if (
            self.rate_limited_requests
            >= self.rate_limit_warning_threshold
        ):
            self.alerts.append(
                {
                    "type": "rate_limit",
                    "severity": "warning",
                    "message": (
                        "Rate-limit count exceeded "
                        "warning threshold."
                    ),
                    "value": self.rate_limited_requests,
                    "threshold": (
                        self.rate_limit_warning_threshold
                    ),
                }
            )

        return self.alerts

    # --------------------------------------------------------
    # Export
    # --------------------------------------------------------

    def export_json(
        self,
        path: str | Path = "outputs/metrics.json",
    ) -> None:

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        self.check_metrics()

        path.write_text(
            json.dumps(
                self.get_metrics(),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    def reset(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.rate_limited_requests = 0
        self.alerts = []