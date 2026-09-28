from __future__ import annotations

import time
from collections import defaultdict, deque

from google.adk.plugins import base_plugin


class RateLimitPlugin(base_plugin.BasePlugin):
    """
    Rate limit theo từng user_id.

    Mặc định:
        10 requests / 60 seconds

    Nếu vượt limit:
        - không cho request đi tiếp
        - trả message Rate limit...
    """

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
    ):
        super().__init__(name="rate_limiter")

        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.requests: dict[str, deque] = defaultdict(deque)

        self.blocked_count = 0
        self.passed_count = 0

    def _get_user_id(self, callback_context) -> str:
        """
        Lấy user_id từ callback context.
        Có fallback để suite/test vẫn chạy được.
        """

        user_id = getattr(callback_context, "user_id", None)

        if user_id:
            return str(user_id)

        session = getattr(callback_context, "session", None)

        if session is not None:
            user_id = getattr(session, "user_id", None)

            if user_id:
                return str(user_id)

        return "anonymous"

    def check(self, user_id: str) -> bool:
        """
        Return True nếu request được phép.
        Return False nếu bị rate limit.
        """

        now = time.monotonic()
        timestamps = self.requests[user_id]

        # Xóa timestamp đã hết cửa sổ
        while timestamps:
            if now - timestamps[0] >= self.window_seconds:
                timestamps.popleft()
            else:
                break

        if len(timestamps) >= self.max_requests:
            self.blocked_count += 1
            return False

        timestamps.append(now)
        self.passed_count += 1

        return True

    async def before_model_callback(
        self,
        *,
        callback_context,
        llm_request,
    ):
        """
        Chặn request trước khi gọi LLM.
        """

        user_id = self._get_user_id(callback_context)

        allowed = self.check(user_id)

        if not allowed:
            return {
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "text": (
                                "Rate limit exceeded. "
                                "Please try again later."
                            )
                        }
                    ],
                }
            }

        return None

    def reset(self):
        """Reset toàn bộ rate-limit state."""

        self.requests.clear()
        self.blocked_count = 0
        self.passed_count = 0