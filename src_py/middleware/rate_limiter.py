import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from typing import Dict, List


class InMemoryRateLimiter:
    def __init__(self, requests_limit: int, window_seconds: int, error_code: str = "slow_down", error_desc: str = "Too many requests"):
        self.limit = requests_limit
        self.window = window_seconds
        self.error_code = error_code
        self.error_desc = error_desc
        self.history: Dict[str, List[float]] = defaultdict(list)

    def check(self, key: str):
        now = time.time()
        # Filter timestamps within window
        valid_timestamps = [ts for ts in self.history[key] if now - ts < self.window]
        if len(valid_timestamps) >= self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": self.error_code,
                    "error_description": self.error_desc
                }
            )
        valid_timestamps.append(now)
        self.history[key] = valid_timestamps


token_limiter = InMemoryRateLimiter(60, 60, "slow_down", "Too many token requests, please try again later.")
register_limiter = InMemoryRateLimiter(30, 900, "slow_down", "Too many client registrations, please try again later.")
auth_limiter = InMemoryRateLimiter(100, 900, "slow_down", "Too many authentication attempts, please try again later.")
admin_login_limiter = InMemoryRateLimiter(10, 900, "slow_down", "Too many login attempts. Account temporarily throttled for 15 minutes.")
