import time
import uuid
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Set, Dict, Any

import jwt

ALGORITHM = "HS256"
DEFAULT_ACCESS_TTL = 900        # 15 min
DEFAULT_REFRESH_TTL = 604800    # 7 days


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: float
    refresh_expires_at: float


@dataclass
class TokenClaims:
    sub: str
    roles: list
    jti: str
    exp: float
    iat: float
    type: str  # "access" or "refresh"


class RevocationStore:
    """In-process revocation store. Swap for Redis in production."""

    def __init__(self):
        self._revoked: Dict[str, float] = {}   # jti -> expires_at

    def revoke(self, jti: str, expires_at: float) -> None:
        self._revoked[jti] = expires_at

    def is_revoked(self, jti: str) -> bool:
        exp = self._revoked.get(jti)
        if exp is None:
            return False
        if time.time() > exp:
            del self._revoked[jti]
            return False
        return True

    def cleanup(self) -> None:
        now = time.time()
        expired = [k for k, v in self._revoked.items() if v < now]
        for k in expired:
            del self._revoked[k]


class JWTAuth:
    def __init__(
        self,
        secret: str,
        issuer: str = "securegate",
        access_ttl: int = DEFAULT_ACCESS_TTL,
        refresh_ttl: int = DEFAULT_REFRESH_TTL,
        revocation_store: Optional[RevocationStore] = None,
    ):
        self._secret = secret
        self._issuer = issuer
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._revocation = revocation_store or RevocationStore()

    # ---- issuance ----

    def issue_token_pair(self, subject: str, roles: Optional[list] = None) -> TokenPair:
        now = time.time()
        access_jti = str(uuid.uuid4())
        refresh_jti = str(uuid.uuid4())

        access_exp = now + self._access_ttl
        refresh_exp = now + self._refresh_ttl

        access_payload = {
            "sub": subject,
            "iss": self._issuer,
            "roles": roles or [],
            "jti": access_jti,
            "type": "access",
            "iat": int(now),
            "exp": int(access_exp),
        }
        refresh_payload = {
            "sub": subject,
            "iss": self._issuer,
            "roles": roles or [],
            "jti": refresh_jti,
            "type": "refresh",
            "iat": int(now),
            "exp": int(refresh_exp),
            "access_jti": access_jti,
        }

        access_token = jwt.encode(access_payload, self._secret, algorithm=ALGORITHM)
        refresh_token = jwt.encode(refresh_payload, self._secret, algorithm=ALGORITHM)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_expires_at=access_exp,
            refresh_expires_at=refresh_exp,
        )

    # ---- validation ----

    def validate_access_token(self, token: str) -> TokenClaims:
        payload = self._decode(token)
        if payload.get("type") != "access":
            raise JWTAuthError("Token is not an access token")
        jti = payload["jti"]
        if self._revocation.is_revoked(jti):
            raise JWTAuthError("Token has been revoked")
        return TokenClaims(
            sub=payload["sub"],
            roles=payload.get("roles", []),
            jti=jti,
            exp=payload["exp"],
            iat=payload["iat"],
            type="access",
        )

    def validate_refresh_token(self, token: str) -> TokenClaims:
        payload = self._decode(token)
        if payload.get("type") != "refresh":
            raise JWTAuthError("Token is not a refresh token")
        jti = payload["jti"]
        if self._revocation.is_revoked(jti):
            raise JWTAuthError("Refresh token has been revoked")
        return TokenClaims(
            sub=payload["sub"],
            roles=payload.get("roles", []),
            jti=jti,
            exp=payload["exp"],
            iat=payload["iat"],
            type="refresh",
        )

    # ---- refresh rotation ----

    def refresh(self, refresh_token: str) -> TokenPair:
        claims = self.validate_refresh_token(refresh_token)
        # Revoke the old refresh token and its sibling access token
        old_payload = self._decode(refresh_token)
        self._revocation.revoke(claims.jti, claims.exp)
        access_jti = old_payload.get("access_jti")
        if access_jti:
            self._revocation.revoke(access_jti, claims.exp)
        # Issue a new pair
        return self.issue_token_pair(subject=claims.sub, roles=claims.roles)

    # ---- revocation ----

    def revoke_access_token(self, token: str) -> None:
        payload = self._decode(token)
        self._revocation.revoke(payload["jti"], payload["exp"])

    def revoke_refresh_token(self, token: str) -> None:
        payload = self._decode(token)
        self._revocation.revoke(payload["jti"], payload["exp"])

    def revoke_token_pair(self, access_token: str, refresh_token: str) -> None:
        self.revoke_access_token(access_token)
        self.revoke_refresh_token(refresh_token)

    # ---- middleware helper ----

    def authenticate(self, auth_header: Optional[str]) -> TokenClaims:
        """Extract and validate bearer token from Authorization header."""
        if not auth_header or not auth_header.startswith("Bearer "):
            raise JWTAuthError("Missing or malformed Authorization header")
        token = auth_header[len("Bearer "):]
        return self.validate_access_token(token)

    # ---- internal ----

    def _decode(self, token: str) -> dict:
        try:
            return jwt.decode(token, self._secret, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError as exc:
            raise JWTAuthError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise JWTAuthError(f"Invalid token: {exc}") from exc


class JWTAuthError(Exception):
    """Raised on any authentication / validation failure."""