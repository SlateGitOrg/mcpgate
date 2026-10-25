"""Token-bucket rate limiting per client and per (client, tool).

Each call must take one token from the caller's client-wide bucket *and*, if the tool matches
a ``per_tool`` glob, from the (client, tool) bucket. Both are checked before either is
debited, so a rejected call never burns budget. Buckets refill continuously
(``tokens = min(burst, tokens + elapsed * rate)``), which makes every operation O(1) time and
O(1) space per tracked key.

Memory is bounded: buckets live in an LRU map capped at ``max_tracked_buckets``. Evicting an
idle bucket is safe because a fresh bucket starts full, and an idle bucket would have refilled
to full anyway once ``burst / rate`` seconds pass; eviction can only grant a caller extra
budget if more than ``max_tracked_buckets`` distinct keys are active at once.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase

from mcpgate.config import RateLimitConfig, RateRule

__all__ = ["RateDecision", "RateLimiter", "TokenBucket"]


@dataclass(slots=True)
class TokenBucket:
    rate: float
    burst: int
    tokens: float
    updated: float

    def refill(self, now: float) -> None:
        if now > self.updated:
            self.tokens = min(float(self.burst), self.tokens + (now - self.updated) * self.rate)
            self.updated = now

    def wait_time(self, cost: float = 1.0) -> float:
        """Seconds until ``cost`` tokens are available (0 if they already are)."""
        missing = cost - self.tokens
        return 0.0 if missing <= 0 else missing / self.rate


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    retry_after_s: float = 0.0
    scope: str | None = None
    """Which budget ran out: ``"client"`` or ``"tool"``."""


class RateLimiter:
    def __init__(self, config: RateLimitConfig, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._cfg = config
        self._clock = clock
        self._buckets: OrderedDict[tuple[str, str | None], TokenBucket] = OrderedDict()

    def _rule_for_tool(self, tool: str) -> tuple[str, RateRule] | None:
        for pattern, rule in self._cfg.per_tool.items():
            if fnmatchcase(tool, pattern):
                return pattern, rule
        return None

    def _bucket(self, key: tuple[str, str | None], rule: RateRule, now: float) -> TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None or bucket.rate != rule.rate or bucket.burst != rule.burst:
            bucket = TokenBucket(rate=rule.rate, burst=rule.burst, tokens=float(rule.burst), updated=now)
            self._buckets[key] = bucket
            while len(self._buckets) > self._cfg.max_tracked_buckets:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
            bucket.refill(now)
        return bucket

    def check(self, client_id: str, tool: str) -> RateDecision:
        """Consume one token for ``client_id`` calling ``tool`` if budget allows."""
        if not self._cfg.enabled:
            return RateDecision(True)
        now = self._clock()
        client_rule = self._cfg.client_overrides.get(client_id, self._cfg.per_client)
        client_bucket = self._bucket((client_id, None), client_rule, now)
        tool_rule = self._rule_for_tool(tool)
        tool_bucket = (
            self._bucket((client_id, f"{tool_rule[0]}"), tool_rule[1], now) if tool_rule is not None else None
        )
        if client_bucket.tokens < 1.0:
            return RateDecision(False, client_bucket.wait_time(), "client")
        if tool_bucket is not None and tool_bucket.tokens < 1.0:
            return RateDecision(False, tool_bucket.wait_time(), "tool")
        client_bucket.tokens -= 1.0
        if tool_bucket is not None:
            tool_bucket.tokens -= 1.0
        return RateDecision(True)

    @property
    def tracked(self) -> int:
        return len(self._buckets)
