"""Small, explicit API-edge controls for the research prototype.

This is intentionally not an enterprise identity platform.  It provides a
single place for bearer-token extraction, environment-owned identities,
fixed-window abuse limits, and endpoint role checks.  Production refuses the
development fixture identities in ``security.tool_security``.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Iterable

from fastapi import HTTPException, Request, status

import config
from security.tool_security import Identity, ToolRole, resolve_server_identity


class FixedWindowRateLimiter:
    """Thread-safe in-memory limiter suitable for one prototype process."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: float = 60.0) -> None:
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and now - events[0] >= window_seconds:
                events.popleft()
            if len(events) >= limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(max(1, int(window_seconds - (now - events[0]))))},
                )
            events.append(now)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


RATE_LIMITER = FixedWindowRateLimiter()


def _bearer_token(request: Request) -> str | None:
    value = request.headers.get("authorization", "").strip()
    if value.lower().startswith("bearer "):
        token = value[7:].strip()
        return token or None
    return None


def resolve_request_identity(request: Request) -> Identity:
    """Resolve a server-owned principal without trusting body/query roles."""
    existing = getattr(request.state, "identity", None)
    if isinstance(existing, Identity):
        return existing
    token = _bearer_token(request)
    # Subject-based development fixtures are for internal callers. HTTP callers
    # must present a token or explicitly opt into the anonymous demo identity.
    identity = (
        resolve_server_identity(None, auth_token=token)
        if token
        else Identity(subject_id="anonymous", role=ToolRole.USER, authenticated=False)
    )
    if request.headers.get("authorization") and (not token or not identity.authenticated):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    if (
        not token
        and config.APP_ENV in {"development", "test"}
        and config.DEVELOPMENT_AUTH_ENABLED
        and config.DEVELOPMENT_ANONYMOUS_DEMO
        and not config.API_AUTH_REQUIRED
    ):
        # A local demo can use only the lowest-privilege fixture.  Client body
        # fields never select a role or a different subject.
        identity = resolve_server_identity("user_default")
        identity.auth_source = "local anonymous demonstration identity"
    if config.APP_ENV == "production" or config.API_AUTH_REQUIRED or not config.DEVELOPMENT_ANONYMOUS_DEMO:
        if not identity.authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    request.state.identity = identity
    return identity


def require_roles(request: Request, roles: Iterable[ToolRole]) -> Identity:
    identity = resolve_request_identity(request)
    if identity.role not in set(roles):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authorization denied")
    return identity


def endpoint_limit(path: str) -> int:
    if path.endswith("/chat"):
        return config.API_RATE_LIMIT_CHAT_PER_MINUTE
    if path.endswith("/analyze"):
        return config.API_RATE_LIMIT_ANALYZE_PER_MINUTE
    return config.API_RATE_LIMIT_ADMIN_PER_MINUTE


def endpoint_bucket(path: str) -> str:
    """Bound key cardinality; resource IDs cannot create fresh rate budgets."""
    if path == "/api/v1/chat":
        return "chat"
    if path in {"/api/v1/analyze", "/api/v1/evaluate"}:
        return "analyze"
    return "admin"
