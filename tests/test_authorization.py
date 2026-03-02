from typing import Dict

import jwt as pyjwt
import requests


class TestRequiredAuthorization:
    """Tests for endpoints using auth.required()."""

    def test_valid_token(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        res = requests.get(f"{test_server}/protected", headers=auth_headers)
        assert res.status_code == 200
        body = res.json()
        assert "sub" in body
        assert body.get("preferred_username") is not None

    def test_missing_token(self, test_server: str) -> None:
        res = requests.get(f"{test_server}/protected")
        assert res.status_code in (401, 403)

    def test_invalid_token(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/protected",
            headers={"Authorization": "Bearer garbage.token.here"},
        )
        assert res.status_code == 401

    def test_expired_token(self, test_server: str) -> None:
        """A self-signed expired token should be rejected."""
        expired = pyjwt.encode(
            {"sub": "test", "exp": 1},
            "secret",
            algorithm="HS256",
            headers={"kid": "fake-kid"},
        )
        res = requests.get(
            f"{test_server}/protected",
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert res.status_code == 401


class TestClaimsAuthorization:
    """Tests for claim-based authorization."""

    def test_valid_claims(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        res = requests.get(
            f"{test_server}/protected-claims", headers=auth_headers
        )
        assert res.status_code == 200

    def test_invalid_claims_rejected(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        res = requests.get(
            f"{test_server}/protected-bad-claims", headers=auth_headers
        )
        assert res.status_code == 401
        assert "claims" in res.json()["detail"].lower()


class TestOptionalAuthorization:
    """Tests for endpoints using auth.optional()."""

    def test_anonymous_access(self, test_server: str) -> None:
        res = requests.get(f"{test_server}/optional")
        assert res.status_code == 200
        assert res.json()["authenticated"] is False

    def test_authenticated_access(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        res = requests.get(f"{test_server}/optional", headers=auth_headers)
        assert res.status_code == 200
        body = res.json()
        assert body["authenticated"] is True
        assert "sub" in body

    def test_bad_token_treated_as_anonymous(self, test_server: str) -> None:
        res = requests.get(
            f"{test_server}/optional",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert res.status_code == 200
        assert res.json()["authenticated"] is False


class TestScopeAuth:
    """Tests for scope enforcement in auth.required(scopes=...)."""

    def test_all_scopes_present(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Token has 'profile' and 'email' → 200."""
        res = requests.get(f"{test_server}/scoped-valid", headers=auth_headers)
        assert res.status_code == 200
        assert "sub" in res.json()

    def test_single_scope_present(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Token has 'profile' → 200."""
        res = requests.get(f"{test_server}/scoped-single", headers=auth_headers)
        assert res.status_code == 200

    def test_all_scopes_missing(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Token lacks 'admin' and 'superuser' → 403."""
        res = requests.get(f"{test_server}/scoped-bad", headers=auth_headers)
        assert res.status_code == 403
        detail = res.json()["detail"].lower()
        assert "missing" in detail
        assert "admin" in detail
        assert "superuser" in detail

    def test_partial_scope_match(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Token has 'profile' but not 'nonexistent-scope' → 403."""
        res = requests.get(f"{test_server}/scoped-partial", headers=auth_headers)
        assert res.status_code == 403
        detail = res.json()["detail"].lower()
        assert "nonexistent-scope" in detail
        # 'profile' should NOT appear in the missing list
        assert "profile" not in detail

    def test_no_token_returns_401(self, test_server: str) -> None:
        """Missing token on a scoped endpoint → 401/403."""
        res = requests.get(f"{test_server}/scoped-valid")
        assert res.status_code in (401, 403)

    def test_invalid_token_returns_401(self, test_server: str) -> None:
        """Bad token → 401 (before scopes are even checked)."""
        res = requests.get(
            f"{test_server}/scoped-valid",
            headers={"Authorization": "Bearer garbage"},
        )
        assert res.status_code == 401


class TestScopeAndClaimsCombined:
    """Tests for endpoints that require both scopes and claims."""

    def test_both_pass(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Scopes and claims both satisfied → 200."""
        res = requests.get(
            f"{test_server}/scoped-and-claims", headers=auth_headers
        )
        assert res.status_code == 200

    def test_scopes_ok_claims_fail(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Scopes pass but claims fail → 401 (claims error)."""
        res = requests.get(
            f"{test_server}/scoped-ok-claims-bad", headers=auth_headers
        )
        assert res.status_code == 401
        assert "claims" in res.json()["detail"].lower()

    def test_scopes_fail_claims_ok(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Scopes fail (checked first) → 403 (scope error)."""
        res = requests.get(
            f"{test_server}/scoped-bad-claims-ok", headers=auth_headers
        )
        assert res.status_code == 403
        assert "scope" in res.json()["detail"].lower()
