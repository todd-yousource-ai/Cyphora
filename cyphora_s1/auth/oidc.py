"""
Cyphora-S1 Auth — OIDC / OAuth 2.0 Integration

BUG 2 FIX: Implements OIDC Authorization Code Flow for SSO.
Supports: Google Workspace, Azure AD, Okta, GitHub, generic OIDC IdP.

Configuration (environment variables):
    CYPHORA_OIDC_CLIENT_ID       — OAuth2 client ID
    CYPHORA_OIDC_CLIENT_SECRET   — OAuth2 client secret
    CYPHORA_OIDC_DISCOVERY_URL   — OIDC discovery endpoint (.well-known/openid-configuration)
    CYPHORA_OIDC_REDIRECT_URI    — Redirect URI registered with IdP
    CYPHORA_OIDC_SCOPES          — Space-separated scopes (default: openid email profile)
    CYPHORA_OIDC_CLAIM_TENANT    — ID token claim for tenant_id (default: tenant_id)
    CYPHORA_OIDC_CLAIM_ROLE      — ID token claim for role (default: cyphora_role)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlencode

import structlog

from cyphora_s1.auth.models import CyphoraUser, Role

logger = structlog.get_logger(__name__)

_CLIENT_ID     = os.getenv("CYPHORA_OIDC_CLIENT_ID",     "")
_CLIENT_SECRET = os.getenv("CYPHORA_OIDC_CLIENT_SECRET", "")
_DISCOVERY_URL = os.getenv("CYPHORA_OIDC_DISCOVERY_URL", "")
_REDIRECT_URI  = os.getenv("CYPHORA_OIDC_REDIRECT_URI",  "https://app.cyphora-s1.io/auth/oidc/callback")
_SCOPES        = os.getenv("CYPHORA_OIDC_SCOPES",        "openid email profile")
_CLAIM_TENANT  = os.getenv("CYPHORA_OIDC_CLAIM_TENANT",  "tenant_id")
_CLAIM_ROLE    = os.getenv("CYPHORA_OIDC_CLAIM_ROLE",    "cyphora_role")

_ROLE_MAP: Dict[str, Role] = {
    "analyst":        Role.ANALYST,
    "senior_analyst": Role.SENIOR_ANALYST,
    "soc_manager":    Role.SOC_MANAGER,
    "admin":          Role.ADMIN,
    "readonly":       Role.READONLY,
}

# In-memory PKCE/state store — use Redis in production
_STATE_STORE: Dict[str, Dict] = {}


def is_configured() -> bool:
    return bool(_CLIENT_ID and _CLIENT_SECRET and _DISCOVERY_URL)


async def _get_discovery(discovery_url: str) -> Dict:
    """Fetch OIDC discovery document."""
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        return resp.json()


def get_authorization_url(
    state: Optional[str] = None, tenant_hint: Optional[str] = None
) -> tuple[str, str]:
    """
    Generate OIDC authorization URL for redirect-based login.
    Returns an (url, state) tuple. The caller must retain `state` — it is the
    CSRF/PKCE key that exchange_code() later requires.

    FIX (CQH-MNT-005): previously every branch returned a bare string, so a
    caller doing `url, state = get_authorization_url()` unpacked the string
    character-by-character and lost the state value.
    """
    if not is_configured():
        logger.warning("oidc_not_configured_returning_stub_url")
        stub_state = state or secrets.token_urlsafe(32)
        return "/auth/oidc/login?stub=true", stub_state

    state    = state or secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    _STATE_STORE[state] = {
        "verifier": verifier,
        "created":  time.time(),
        "tenant":   tenant_hint,
    }

    params = {
        "client_id":             _CLIENT_ID,
        "response_type":         "code",
        "scope":                 _SCOPES,
        "redirect_uri":          _REDIRECT_URI,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    if tenant_hint:
        params["login_hint"] = tenant_hint

    logger.info("oidc_authorization_redirect", state=state[:8] + "...")
    # In production fetch discovery URL to get authorization_endpoint
    url = (
        f"{_DISCOVERY_URL.replace('/.well-known/openid-configuration', '/authorize')}"
        f"?{urlencode(params)}"
    )
    return url, state


async def exchange_code(code: str, state: str) -> CyphoraUser:
    """
    Exchange an authorization code for tokens and return a CyphoraUser.
    Validates state and PKCE code_verifier.
    """
    if not is_configured():
        # FIX (CQH-SEC-003): previously this returned a valid ANALYST user for
        # ANY code whenever the OIDC env vars were unset (the default state),
        # i.e. a silent authentication bypass. Fail closed. A local dev stub is
        # available only behind an explicit opt-in flag.
        if os.getenv("CYPHORA_AUTH_DEV_STUB", "").lower() in ("1", "true", "yes"):
            logger.warning("oidc_stub_mode_dev_only_accepting_any_code")
            return CyphoraUser(
                user_id="stub-" + str(uuid.uuid4()),
                email="dev@cyphora-s1.local",
                tenant_id="dev",
                role=Role.ANALYST,
                display_name="Dev User (OIDC Stub)",
            )
        raise ValueError(
            "OIDC is not configured. Set the OIDC provider environment "
            "variables (or CYPHORA_AUTH_DEV_STUB=1 for local development)."
        )

    state_data = _STATE_STORE.pop(state, None)
    if not state_data:
        raise ValueError("Invalid or expired state parameter")
    if time.time() - state_data["created"] > 600:
        raise ValueError("State parameter expired (>10 minutes)")

    import httpx
    discovery = await _get_discovery(_DISCOVERY_URL)

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            discovery["token_endpoint"],
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  _REDIRECT_URI,
                "client_id":     _CLIENT_ID,
                "client_secret": _CLIENT_SECRET,
                "code_verifier": state_data["verifier"],
            },
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

    import jwt as pyjwt
    # FIX (CQH-SEC-002): verify the id_token signature against the IdP's JWKS
    # and validate audience/issuer/expiry. Previously the token was decoded
    # with verify_signature=False and the (unverified) cyphora_role claim was
    # mapped straight to a role — an attacker who could present an id_token with
    # cyphora_role=admin obtained an authenticated admin user.
    id_token = tokens.get("id_token", "")
    if not id_token:
        raise ValueError("OIDC token response missing id_token")

    jwks_uri = discovery.get("jwks_uri")
    issuer = discovery.get("issuer")
    if not jwks_uri:
        raise ValueError("OIDC discovery document missing jwks_uri")

    jwk_client = pyjwt.PyJWKClient(jwks_uri)
    signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    claims = pyjwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "ES256"],
        audience=_CLIENT_ID,
        issuer=issuer,
        options={"require": ["exp", "iat"]},
    )

    email     = claims.get("email", "")
    tenant_id = claims.get(_CLAIM_TENANT, state_data.get("tenant") or "default")
    role_str  = claims.get(_CLAIM_ROLE, "analyst").lower()
    role      = _ROLE_MAP.get(role_str, Role.ANALYST)

    if not email:
        raise ValueError("OIDC id_token missing email claim")

    user = CyphoraUser(
        user_id      = claims.get("sub", str(uuid.uuid4())),
        email        = email,
        tenant_id    = tenant_id,
        role         = role,
        display_name = claims.get("name", email),
    )
    logger.info("oidc_login_success", email=email, tenant_id=tenant_id, role=role.value)
    return user


# Required for authorization URL generation with PKCE
import base64
