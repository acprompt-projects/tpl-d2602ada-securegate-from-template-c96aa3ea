===
import asyncio
import time
import pytest
from rate_limiter import (
    RateLimiter, InMemoryBackend, Tier, TierConfig,
    RateLimitResult, AbuseRule, DEFAULT_TIER_CONFIGS,
)

@pytest.fixture
def limiter():
    return RateLimiter()

@pytest.fixture
def fast_limiter():
    clock = lambda: 1000.0
    lm = RateLimiter(clock=clock)
    lm._clock = clock
    return lm

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

class TestInMemoryBackend:
    def test_basic_increment(self):
        backend = InMemoryBackend()
        count, reset = run(backend.incr_sliding_window("k", 60, 100.0))
        assert count == 1

    def test_sliding_window_expires_old(self):
        backend = InMemoryBackend()
        run(backend.incr_sliding_window("k", 10, 100.0))
        count, _ = run(backend.incr_sliding_window("k", 10, 115.0))
        assert count == 1

    def test_sliding_window_keeps_recent(self):
        backend = InMemoryBackend()
        run(backend.incr_sliding_window("k", 10, 100.0))
        count, _ = run(backend.incr_sliding_window("k", 10, 105.0))
        assert count == 2

class TestRateLimiter:
    def test_first_request_allowed(self, limiter):
        result = run(limiter.check("user1"))
        assert result.allowed is True
        assert result.remaining == DEFAULT_TIER_CONFIGS[Tier.FREE].requests - 1

    def test_tier_respected(self, limiter):
        result = run(limiter.check("user1", tier=Tier.PREMIUM))
        assert result.limit == DEFAULT_TIER_CONFIGS[Tier.PREMIUM].requests

    def test_override_limit(self, limiter):
        result = run(limiter.check("user1", override_limit=5, override_window=10))
        assert result.limit == 5

    def test_rate_limit_exceeded(self, fast_limiter):
        for i in range(60):
            fast_limiter._clock = lambda: 1000.0 + i * 0.001
            run(fast_limiter.check("user1", override_limit=5, override_window=60))
        fast_limiter._clock = lambda: 1000.06
        result = run(fast_limiter.check("user1", override_limit=5, override_window=60))
        assert result.allowed is False
        assert result.retry_after is not None

    def test_separate_keys_independent(self, limiter):
        r1 = run(limiter.check("user1", override_limit=2, override_window=60))
        r2 = run(limiter.check("user2", override_limit=2, override_window=60))
        assert r1.allowed is True
        assert r2.allowed is True

    def test_scopes_independent(self, limiter):
        run(limiter.check("user1", scope="api", override_limit=1, override_window=60))
        result = run(limiter.check("user1", scope="web", override_limit=1, override_window=60))
        assert result.allowed is True

class TestAbuseProtection:
    def test_abuse_block(self):
        clock_times = [1000.0]
        limiter = RateLimiter(
            abuse_rules={"api": AbuseRule(threshold=3, window_seconds=60, block_duration_seconds=300)},
            clock=lambda: clock_times[0],
        )
        for i in range(6):
            clock_times[0] = 1000.0 + i
            run(limiter.check("abuser", scope="api", override_limit=2, override_window=60))
        result = run(limiter.check("abuser", scope="api", override_limit=2, override_window=60))
        assert result.allowed is False
        assert result.retry_after is not None

    def test_manual_block_unblock(self):
        limiter = RateLimiter(clock=lambda: 1000.0)
        run(limiter.block("bad_actor", 300))
        result = run(limiter.check("bad_actor"))
        assert result.allowed is False
        run(limiter.unblock("bad_actor"))
        result = run(limiter.check("bad_actor"))
        assert result.allowed is True

class TestGatewayMiddleware:
    @pytest.mark.asyncio
    async def test_middleware_allows(self):
        limiter = RateLimiter(clock=lambda: 1000.0)
        resolver = lambda req: asyncio.coroutine(lambda: (req.get("ip", "1.2.3.4"), Tier.STANDARD))()
        async def async_resolver(req):
            return req.get("ip", "1.2.3.4"), Tier.STANDARD
        mw = limiter.gateway_middleware(async_resolver, scope="api")
        result = await mw({"ip": "1.2.3.4"})
        assert result["allowed"] is True
        assert "X-RateLimit-Limit" in result["headers"]

    @pytest.mark.asyncio
    async def test_middleware_blocks_on_limit(self):
        t = 1000.0
        limiter = RateLimiter(clock=lambda: t, tier_configs={Tier.FREE: TierConfig(2, 60)})
        async def resolver(req):
            return "u1", Tier.FREE
        mw = limiter.gateway_middleware(resolver, scope="api")
        await mw({})
        await mw({})
        result = await mw({})
        assert result["allowed"] is False
        assert result["status"] == 429

class TestTiers:
    def test_custom_tier_configs(self):
        custom = {Tier.FREE: TierConfig(10, 30)}
        limiter = RateLimiter(tier_configs=custom)
        result = run(limiter.check("u1", tier=Tier.FREE))
        assert result.limit == 10

    def test_all_tiers_have_defaults(self):
        for tier in Tier:
            assert tier in DEFAULT_TIER_CONFIGS