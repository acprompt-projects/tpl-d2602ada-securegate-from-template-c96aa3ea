import time
import jwt as pyjwt
import pytest

from jwt_auth import JWTAuth, JWTAuthError, RevocationStore, ALGORITHM


@pytest.fixture
def auth():
    return JWTAuth(secret="test-secret-key-at-least-32-chars!", issuer="test-gateway")


@pytest.fixture
def auth_short_ttl():
    return JWTAuth(
        secret="test-secret-key-at-least-32-chars!",
        access_ttl=1,
        refresh_ttl=2,
    )


class TestIssueTokenPair:
    def test_issues_valid_pair(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["admin"])
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_expires_at < pair.refresh_expires_at

    def test_access_token_claims(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["viewer"])
        payload = pyjwt.decode(pair.access_token, auth._secret, algorithms=[ALGORITHM])
        assert payload["sub"] == "user-1"
        assert payload["roles"] == ["viewer"]
        assert payload["type"] == "access"
        assert payload["iss"] == "test-gateway"
        assert "jti" in payload

    def test_refresh_token_claims(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["viewer"])
        payload = pyjwt.decode(pair.refresh_token, auth._secret, algorithms=[ALGORITHM])
        assert payload["type"] == "refresh"
        assert "access_jti" in payload

    def test_default_roles_empty(self, auth):
        pair = auth.issue_token_pair("user-2")
        claims = auth.validate_access_token(pair.access_token)
        assert claims.roles == []


class TestValidateAccessToken:
    def test_valid_token(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["admin"])
        claims = auth.validate_access_token(pair.access_token)
        assert claims.sub == "user-1"
        assert claims.roles == ["admin"]
        assert claims.type == "access"

    def test_expired_token(self, auth_short_ttl):
        pair = auth_short_ttl.issue_token_pair("user-1")
        time.sleep(1.5)
        with pytest.raises(JWTAuthError, match="expired"):
            auth_short_ttl.validate_access_token(pair.access_token)

    def test_refresh_token_rejected_as_access(self, auth):
        pair = auth.issue_token_pair("user-1")
        with pytest.raises(JWTAuthError, match="not an access token"):
            auth.validate_access_token(pair.refresh_token)

    def test_wrong_secret_fails(self, auth):
        pair = auth.issue_token_pair("user-1")
        bad_auth = JWTAuth(secret="wrong-secret-key-at-least-32-chars!!")
        with pytest.raises(JWTAuthError):
            bad_auth.validate_access_token(pair.access_token)


class TestRefreshRotation:
    def test_refresh_issues_new_pair(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["editor"])
        new_pair = auth.refresh(pair.refresh_token)
        assert new_pair.access_token != pair.access_token
        assert new_pair.refresh_token != pair.refresh_token
        claims = auth.validate_access_token(new_pair.access_token)
        assert claims.sub == "user-1"
        assert claims.roles == ["editor"]

    def test_old_refresh_is_revoked(self, auth):
        pair = auth.issue_token_pair("user-1")
        auth.refresh(pair.refresh_token)
        with pytest.raises(JWTAuthError, match="revoked"):
            auth.validate_refresh_token(pair.refresh_token)

    def test_old_access_is_revoked_after_refresh(self, auth):
        pair = auth.issue_token_pair("user-1")
        auth.refresh(pair.refresh_token)
        with pytest.raises(JWTAuthError, match="revoked"):
            auth.validate_access_token(pair.access_token)

    def test_reuse_of_old_refresh_detected(self, auth):
        pair = auth.issue_token_pair("user-1")
        auth.refresh(pair.refresh_token)
        with pytest.raises(JWTAuthError):
            auth.refresh(pair.refresh_token)


class TestRevocation:
    def test_revoke_access_token(self, auth):
        pair = auth.issue_token_pair("user-1")
        auth.revoke_access_token(pair.access_token)
        with pytest.raises(JWTAuthError, match="revoked"):
            auth.validate_access_token(pair.access_token)

    def test_revoke_token_pair(self, auth):
        pair = auth.issue_token_pair("user-1")
        auth.revoke_token_pair(pair.access_token, pair.refresh_token)
        with pytest.raises(JWTAuthError):
            auth.validate_access_token(pair.access_token)
        with pytest.raises(JWTAuthError):
            auth.validate_refresh_token(pair.refresh_token)


class TestAuthenticateMiddleware:
    def test_valid_bearer(self, auth):
        pair = auth.issue_token_pair("user-1", roles=["admin"])
        claims = auth.authenticate(f"Bearer {pair.access_token}")
        assert claims.sub == "user-1"

    def test_missing_header(self, auth):
        with pytest.raises(JWTAuthError, match="Missing"):
            auth.authenticate(None)

    def test_malformed_header(self, auth):
        with pytest.raises(JWTAuthError, match="Missing"):
            auth.authenticate("Token abc123")

    def test_expired_bearer(self, auth_short_ttl):
        pair = auth_short_ttl.issue_token_pair("user-1")
        time.sleep(1.5)
        with pytest.raises(JWTAuthError, match="expired"):
            auth_short_ttl.authenticate(f"Bearer {pair.access_token}")


class TestRevocationStore:
    def test_cleanup_removes_expired(self):
        store = RevocationStore()
        store.revoke("jti-old", time.time() - 10)
        store.revoke("jti-new", time.time() + 3600)
        store.cleanup()
        assert not store.is_revoked("jti-old")
        assert store.is_revoked("jti-new")