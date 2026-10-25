from __future__ import annotations

import pytest

from mcpgate.config import RateLimitConfig, RateRule
from mcpgate.ratelimit import RateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make(**kw: object) -> tuple[RateLimiter, Clock]:
    clock = Clock()
    cfg = RateLimitConfig(**kw)  # type: ignore[arg-type]
    return RateLimiter(cfg, clock=clock), clock


def test_burst_then_refill() -> None:
    limiter, clock = make(per_client=RateRule(rate=2, burst=3))
    assert [limiter.check("a", "t").allowed for _ in range(4)] == [True, True, True, False]
    denied = limiter.check("a", "t")
    assert denied.scope == "client"
    assert denied.retry_after_s == pytest.approx(0.5)
    clock.now += 0.5
    assert limiter.check("a", "t").allowed
    assert not limiter.check("a", "t").allowed


def test_clients_are_isolated_and_overrides_apply() -> None:
    limiter, _ = make(
        per_client=RateRule(rate=1, burst=1), client_overrides={"vip": RateRule(rate=1, burst=5)}
    )
    assert limiter.check("a", "t").allowed
    assert not limiter.check("a", "t").allowed
    assert limiter.check("b", "t").allowed
    assert sum(limiter.check("vip", "t").allowed for _ in range(6)) == 5


def test_per_tool_budget_and_no_debit_on_rejection() -> None:
    limiter, clock = make(
        per_client=RateRule(rate=1, burst=10), per_tool={"inv__adjust_*": RateRule(rate=0.1, burst=1)}
    )
    assert limiter.check("a", "inv__adjust_stock").allowed
    denied = limiter.check("a", "inv__adjust_stock")
    assert (denied.allowed, denied.scope) == (False, "tool")
    assert denied.retry_after_s == pytest.approx(10.0)
    # the rejected call did not consume client budget: 9 tokens remain for other tools
    assert sum(limiter.check("a", "inv__get_stock").allowed for _ in range(10)) == 9
    clock.now += 10
    assert limiter.check("a", "inv__adjust_other").allowed  # shared per-rule budget refilled


def test_disabled_and_bounded_memory() -> None:
    limiter, _ = make(enabled=False)
    assert all(limiter.check("a", "t").allowed for _ in range(100))
    limiter, _ = make(per_client=RateRule(rate=1, burst=1), max_tracked_buckets=16)
    for i in range(100):
        limiter.check(f"client-{i}", "t")
    assert limiter.tracked == 16


def test_config_change_resets_bucket() -> None:
    limiter, _ = make(per_client=RateRule(rate=1, burst=1))
    assert limiter.check("a", "t").allowed
    limiter._cfg = RateLimitConfig(per_client=RateRule(rate=1, burst=3))
    assert limiter.check("a", "t").allowed
