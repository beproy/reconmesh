"""
API key authentication and per-key rate limiting.

Used by protected endpoints via FastAPI's Depends() system:

    from auth import require_api_key

    @router.post("/enrich", dependencies=[Depends(require_api_key)])
    def enrich(...): ...

Storage model: only SHA-256 hashes of keys are persisted. The raw key
is shown to the user exactly once at mint time (see routes/admin.py).
"""
import hashlib
import hmac
import os
import secrets
from datetime import timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
import redis

from database import get_db
from models import ApiKey, utc_now


# ----------------------------------------------------------------------------
# Redis connection — reused for rate limit counters
# ----------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
_redis = redis.Redis.from_url(REDIS_URL, decode_responses=True)


# ----------------------------------------------------------------------------
# Key generation & hashing
# ----------------------------------------------------------------------------
KEY_PREFIX = "rm_"  # so a leaked key is immediately recognizable as ReconMesh


def generate_api_key() -> str:
    """Return a fresh raw API key. Shown to user ONCE, never stored."""
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest. Deterministic — same input always hashes the same."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------------
# Rate limiting (per-key, fixed 1-minute buckets)
# ----------------------------------------------------------------------------
RATE_LIMIT_PER_MINUTE = 60


def check_rate_limit(key_id: int) -> None:
    """Raise 429 if this key has exceeded its per-minute budget."""
    # Bucket by UTC minute. e.g. "ratelimit:5:202605122140"
    minute_bucket = utc_now().strftime("%Y%m%d%H%M")
    redis_key = f"ratelimit:{key_id}:{minute_bucket}"

    current = _redis.incr(redis_key)
    if current == 1:
        # First hit in this bucket — set it to auto-expire so Redis stays clean.
        # 90s = 60s window + buffer to avoid edge races at minute boundaries.
        _redis.expire(redis_key, 90)

    if current > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({RATE_LIMIT_PER_MINUTE}/min)",
        )


# ----------------------------------------------------------------------------
# FastAPI dependency
# ----------------------------------------------------------------------------
def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> ApiKey:
    """
    Validate the X-API-Key header, enforce rate limits, return the key row.

    Used as: Depends(require_api_key) on protected routes.
    Raises 401 for missing / invalid / revoked keys; 429 for rate limit.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )

    incoming_hash = hash_api_key(x_api_key)

    # Lookup by hash (unique-indexed column → fast).
    key_row = db.query(ApiKey).filter(ApiKey.key_hash == incoming_hash).first()

    # Constant-time compare even though we just queried by exact match —
    # belt-and-suspenders against any future change that loosens the query.
    if key_row is None or not hmac.compare_digest(key_row.key_hash, incoming_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if key_row.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked",
        )

    check_rate_limit(key_row.id)

    # Touch last_used_at for visibility into key usage
    key_row.last_used_at = utc_now()
    db.commit()

    return key_row