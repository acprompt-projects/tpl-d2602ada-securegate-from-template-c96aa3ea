===
import time
import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Awaitable, Dict, Any, List, Tuple

class Tier(Enum):
    FREE = "free"
    STANDARD = "standard"
    PREMIUM = "premium"
    INTERNAL = "internal"

@dataclass(frozen=True)
class TierConfig:
    requests: int
    window_seconds: int

DEFAULT_TIER_CONFIGS: Dict[Tier, TierConfig] = {
    Tier.FREE:      TierConfig(requests=60,   window_seconds=60),
    Tier.STANDARD:  TierConfig(requests=300,  window_seconds=60),
    Tier.PREMIUM:   TierConfig(requests=1000, window_seconds=60),
    Tier.INTERNAL:  TierConfig(requests=5000, window_seconds=60),
}

@dataclass
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_at: float
    retry_after: Optional[float] = None

class StorageBackend:
    async def incr_sliding_window(self, key: str, window: int, now: float) -> Tuple[int, float]:
        raise NotImplementedError
    async def close(self) -> None:
        pass

class InMemoryBackend(StorageBackend):
    def __init__(self):
        self._data: Dict[str, List[float]] = {}

    async def incr_sliding_window(self, key: str, window: int, now: float) -> Tuple[int, float]:
        cutoff = now - window
        if key not in self._data:
            self._data[key] = []
        self._data[key] = [t for t in self._data[key] if t > cutoff]
        self._data[key].append(now)
        count = len(self._data[key])
        reset_at = self._data[key][0] + window if self._data[key] else now + window
        return count, reset_at

    async def close(self) -> None:
        self._data.clear()

class RedisBackend(StorageBackend):
    def __init__(self, redis_client: Any, prefix: str = "rl:"):
        self._redis = redis_client
        self._prefix = prefix

    async def incr_sliding_window(self, key: str, window: int, now: float) -> Tuple[int, float]:
        full_key = f"{self._prefix}{key}"
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(full_key, 0, now - window)
        pipe.zadd(full_key, {str(now): now})
        pipe.zcard(full_key)
        pipe.expire(full_key, window + 1)
        results = await pipe.execute()
        count = results[2]
        earliest = await self._redis.zrange(full_key, 0, 0, withscores=True)
        reset_at = (earliest[0][1] + window) if earliest else now + window
        return count, reset_at

@dataclass
class AbuseRule:
    threshold: int
    window_seconds: int
    action: str = "block"
    block_duration_seconds: int = 300

class RateLimiter:
    def __init__(
        self,
        backend: Optional[StorageBackend] = None,
        tier_configs: Optional[Dict[Tier, TierConfig]] = None,
        abuse_rules: Optional[Dict[str, AbuseRule]] = None,
        key_prefix: str = "",
        clock: Optional[Callable[[], float]] = None,
    ):
        self._backend = backend or InMemoryBackend()
        self._tier_configs = tier_configs or DEFAULT_TIER_CONFIGS
        self._abuse_rules = abuse_rules or {}
        self._key_prefix = key_prefix
        self._clock = clock or time.time
        self._blocked: Dict[str, float] = {}

    def _resolve_tier(self, tier: Optional[Tier]) -> Tier:
        return tier if tier is not None else Tier.FREE

    def _make_key(self, identity: str, scope: str) -> str:
        return f"{self._key_prefix}{scope}:{identity}"

    async def check(
        self,
        identity: str,
        scope: str = "default",
        tier: Optional[Tier] = None,
        override_limit: Optional[int] = None,
        override_window: Optional[int] = None,
    ) -> RateLimitResult:
        now = self._clock()
        if identity in self._blocked:
            if now < self._blocked[identity]:
                return RateLimitResult(
                    allowed=False, limit=0, remaining=0,
                    reset_at=self._blocked[identity], retry_after=self._blocked[identity] - now,
                )
            del self._blocked[identity]

        resolved_tier = self._resolve_tier(tier)
        cfg = self._tier_configs[resolved_tier]
        limit = override_limit if override_limit is not None else cfg.requests
        window = override_window if override_window is not None else cfg.window_seconds

        key = self._make_key(identity, scope)
        count, reset_at = await self._backend.incr_sliding_window(key, window, now)
        remaining = max(0, limit - count)
        allowed = count <= limit
        retry_after = (reset_at - now) if not allowed else None

        if not allowed:
            await self._evaluate_abuse(identity, scope, now)

        return RateLimitResult(
            allowed=allowed, limit=limit, remaining=remaining,
            reset_at=reset_at, retry_after=retry_after,
        )

    async def _evaluate_abuse(self, identity: str, scope: str, now: float) -> None:
        rule = self._abuse_rules.get(scope)
        if rule and rule.action == "block":
            abuse_key = self._make_key(identity, f"{scope}:abuse")
            abuse_count, _ = await self._backend.incr_sliding_window(
                abuse_key, rule.window_seconds, now
            )
            if abuse_count >= rule.threshold:
                self._blocked[identity] = now + rule.block_duration_seconds

    async def block(self, identity: str, duration_seconds: int = 300) -> None:
        self._blocked[identity] = self._clock() + duration_seconds

    async def unblock(self, identity: str) -> None:
        self._blocked.pop(identity, None)

    async def close(self) -> None:
        await self._backend.close()

    def gateway_middleware(
        self,
        identity_resolver: Callable[[Dict[str, Any]], Awaitable[Tuple[str, Tier]]],
        scope: str = "api",
    ) -> Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]:
        limiter = self
        async def middleware(request: Dict[str, Any]) -> Dict[str, Any]:
            identity, tier = await identity_resolver(request)
            result = await limiter.check(identity, scope=scope, tier=tier)
            headers = {
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": str(result.remaining),
                "X-RateLimit-Reset": str(int(result.reset_at)),
            }
            if not result.allowed:
                headers["Retry-After"] = str(int(result.retry_after or 1))
                return {"allowed": False, "status": 429, "headers": headers, "body": "Rate limit exceeded"}
            return {"allowed": True, "status": 200, "headers": headers, "body": None}
        return middleware