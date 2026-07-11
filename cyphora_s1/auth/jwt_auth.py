"""
Cyphora-S1 Auth — JWT Authentication Middleware

BUG 2 FIX: Implements JWT-based authentication for all Cyphora-S1 API
endpoints.  Every request must carry a valid Bearer token in the
Authorization header.  The token is validated against the configured
SECRET_KEY and the decoded payload populates a CyphoraUser context.

Configuration via environment variables:
    CYPHORA_JWT_SECRET      — signing secret (required, ≥32 chars)
    CYPHORA_JWT_ALGORITHM   — default: HS256
    CYPHORA_JWT_EXPIRE_MINS — default: 480 (8 hours)

Usage (FastAPI):
    from cyphora_s1.auth.jwt_auth import get_current_user, require_role
    from cyphora_s1.auth.models import Role

    @app.get("/api/v1/investigations")
    async def list_investigations(user: CyphoraUser = Depends(get_current_user)):
        ...

    @app.post("/api/v1/actions/isolate")
    async def isolate(user: CyphoraUser = Depends(require_role(Role.SOC_MANAGER))):
        ...
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

import structlog

from cyphora_s1.auth.models import CyphoraUser, Role, TokenPayload

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    pass


_DEFAULT_SECRET = "CHANGE_ME_USE_32PLUS_CHARS_IN_PRODUCTION"
_SECRET      = os.getenv("CYPHORA_JWT_SECRET", _DEFAULT_SECRET)
_ALGORITHM   = os.getenv("CYPHORA_JWT_ALGORITHM", "HS256")
_EXPIRE_MINS = int(os.getenv("CYPHORA_JWT_EXPIRE_MINS", "480"))


def _require_secure_secret() -> str:
    """
    Return the configured signing secret, or raise if it is missing, the
    shipped default, or too short.

    FIX (CQH-SEC-004): any deployment that omits CYPHORA_JWT_SECRET previously
    signed and verified every session token with a publicly known constant,
    letting an attacker forge admin tokens offline. Fail closed instead. Set
    CYPHORA_AUTH_DEV_STUB=1 to permit an insecure secret in local development
    only (never in production).
    """
    dev_stub = os.getenv("CYPHORA_AUTH_DEV_STUB", "").lower() in ("1", "true", "yes")
    if _SECRET == _DEFAULT_SECRET or not _SECRET:
        if dev_stub:
            logger.warning("jwt_using_insecure_default_secret_dev_stub")
            return _SECRET
        raise AuthenticationError(
            "CYPHORA_JWT_SECRET is unset or the shipped default. Set a unique "
            "secret of at least 32 characters before issuing or verifying tokens."
        )
    if len(_SECRET) < 32 and not dev_stub:
        raise AuthenticationError(
            "CYPHORA_JWT_SECRET must be at least 32 characters."
        )
    return _SECRET


# ─────────────────────────────────────────────
# Token creation
# ─────────────────────────────────────────────

def create_access_token(user: CyphoraUser, expires_minutes: int = _EXPIRE_MINS) -> str:
    """Create a signed JWT for the given user."""
    try:
        import jwt as pyjwt
    except ImportError:
        raise ImportError("PyJWT is required: pip install PyJWT cryptography")

    now    = datetime.now(tz=timezone.utc)
    expiry = now + timedelta(minutes=expires_minutes)
    payload = {
        "user_id":   user.user_id,
        "email":     user.email,
        "tenant_id": user.tenant_id,
        "role":      user.role.value,
        "exp":       expiry.timestamp(),
        "iat":       now.timestamp(),
        "jti":       str(uuid.uuid4()),
    }
    token = pyjwt.encode(payload, _require_secure_secret(), algorithm=_ALGORITHM)
    logger.info("jwt_token_created", user_id=user.user_id, tenant_id=user.tenant_id,
                expires_at=expiry.isoformat())
    return token


# ─────────────────────────────────────────────
# Token verification
# ─────────────────────────────────────────────


def verify_token(token: str) -> TokenPayload:
    """
    Decode and validate a JWT.  Raises AuthenticationError on any
    validation failure (expired, invalid signature, malformed).
    """
    try:
        import jwt as pyjwt
        from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
    except ImportError:
        raise ImportError("PyJWT is required: pip install PyJWT cryptography")

    try:
        payload = pyjwt.decode(token, _require_secure_secret(), algorithms=[_ALGORITHM])
        return TokenPayload(
            user_id   = payload["user_id"],
            email     = payload["email"],
            tenant_id = payload["tenant_id"],
            role      = payload["role"],
            exp       = float(payload["exp"]),
            iat       = float(payload["iat"]),
            jti       = payload.get("jti", ""),
        )
    except ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except InvalidTokenError as exc:
        raise AuthenticationError(f"Invalid token: {exc}")
    except KeyError as exc:
        raise AuthenticationError(f"Token missing required claim: {exc}")


def get_user_from_token(token: str) -> CyphoraUser:
    """Decode a token and return a CyphoraUser, raising AuthenticationError on failure."""
    payload = verify_token(token)
    try:
        role = Role(payload.role)
    except ValueError:
        raise AuthenticationError(f"Unknown role '{payload.role}' in token")
    return CyphoraUser(
        user_id   = payload.user_id,
        email     = payload.email,
        tenant_id = payload.tenant_id,
        role      = role,
    )


# ─────────────────────────────────────────────
# FastAPI dependency helpers
# ─────────────────────────────────────────────

async def get_current_user(authorization: Optional[str] = None) -> CyphoraUser:
    """
    FastAPI dependency that extracts and validates the Bearer token.

    Usage:
        from fastapi import Depends, Header
        from cyphora_s1.auth.jwt_auth import get_current_user

        @router.get("/protected")
        async def protected(
            authorization: Optional[str] = Header(None),
            user: CyphoraUser = Depends(get_current_user),
        ):
            ...
    """
    if not authorization:
        raise AuthenticationError("Missing Authorization header")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthenticationError("Authorization header must be 'Bearer <token>'")
    return get_user_from_token(parts[1])


def require_role(*required_roles: Role):
    """
    FastAPI dependency factory that enforces role membership.

    Usage:
        @router.post("/isolate")
        async def isolate(user = Depends(require_role(Role.SOC_MANAGER, Role.ADMIN))):
            ...
    """
    async def _check(authorization: Optional[str] = None) -> CyphoraUser:
        user = await get_current_user(authorization)
        if user.role not in required_roles:
            raise AuthenticationError(
                f"Role '{user.role.value}' is not permitted. "
                f"Required: {[r.value for r in required_roles]}"
            )
        return user
    return _check


# ─────────────────────────────────────────────
# RBAC action check (non-FastAPI usage)
# ─────────────────────────────────────────────

def assert_can_execute(user: CyphoraUser, action: str) -> None:
    """
    Raise AuthenticationError if the user's role does not permit
    executing the named action.  Call this inside ActionExecutor
    or PlaybookEngine before running any action.
    """
    if not user.can_execute(action):
        raise AuthenticationError(
            f"User '{user.email}' (role: {user.role.value}) "
            f"is not permitted to execute action '{action}'."
        )
    logger.debug("rbac_action_permitted", user=user.email,
                 role=user.role.value, action=action)
