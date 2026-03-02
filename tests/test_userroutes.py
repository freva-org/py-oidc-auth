"""Userinfo and query_user tests.

TestUserinfoEndpoint uses the parametrized ``test_server`` fixture,
so it runs against all installed backends automatically.
"""

from typing import Dict
from unittest.mock import patch

import pytest
import requests
from pytest_mock import MockerFixture

from py_oidc_auth.exceptions import InvalidRequest
from py_oidc_auth.utils import OIDCConfig, get_userinfo, query_user


class TestUserinfoEndpoint:
    """Tests for GET /auth/v2/userinfo."""

    def test_userinfo_with_valid_token(
        self, test_server: str, auth_headers: Dict[str, str]
    ) -> None:
        """Real Keycloak token returns user info."""
        res = requests.get(
            f"{test_server}/api/test/auth/v2/userinfo",
            headers=auth_headers,
            timeout=5,
        )
        assert res.status_code == 200
        js = res.json()
        assert "username" in js
        assert "last_name" in js
        assert "first_name" in js
        assert "pw_name" in js

    def test_userinfo_without_token(self, test_server: str) -> None:
        """Missing token → 401/403."""
        res = requests.get(f"{test_server}/api/test/auth/v2/userinfo")
        assert res.status_code in (401, 403)

    def test_userinfo_with_invalid_token(self, test_server: str) -> None:
        """Invalid token → 401."""
        res = requests.get(
            f"{test_server}/api/test/auth/v2/userinfo",
            headers={"Authorization": "Bearer invalid-garbage"},
        )
        assert res.status_code == 401

    def test_userinfo_fallback_to_userinfo_endpoint(
        self,
        test_server: str,
        auth_headers: Dict[str, str],
        mocker: MockerFixture,
    ) -> None:
        """When token data alone is insufficient, falls back to userinfo endpoint."""
        call_count = 0
        original_get_userinfo = get_userinfo

        def _conditional_userinfo(data: Dict[str, str]) -> Dict[str, str]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "email": "",
                    "username": "",
                    "first_name": "",
                    "last_name": "",
                }
            return original_get_userinfo(data)

        mocker.patch(
            "py_oidc_auth.utils.get_userinfo",
            side_effect=_conditional_userinfo,
        )
        print("fofo", auth_headers)
        res = requests.get(
            f"{test_server}/api/test/auth/v2/userinfo",
            headers=auth_headers,
            timeout=5,
        )
        # Should not be a 500 regardless of backend
        assert res.status_code < 500


class TestQueryUser:
    """Unit tests for query_user."""

    @pytest.mark.asyncio
    async def test_direct_extraction(self, oidc_config: OIDCConfig) -> None:
        """When token_data has enough info, no fallback needed."""
        result = await query_user(
            {
                "preferred_username": "jane",
                "email": "jane@example.com",
                "given_name": "Jane",
                "family_name": "Doe",
            },
            authorization="Bearer fake",
            cfg=oidc_config,
        )
        assert result.username == "jane"
        assert result.email == "jane@example.com"

    @pytest.mark.asyncio
    async def test_incomplete_data_raises_without_fallback(
        self, oidc_config: OIDCConfig
    ) -> None:
        """When token_data is empty and fallback also fails → InvalidRequest."""
        with patch(
            "py_oidc_auth.utils.oidc_request",
            side_effect=InvalidRequest(status_code=502, detail="fail"),
        ):
            with pytest.raises(InvalidRequest):
                await query_user(
                    {},
                    authorization="Bearer fake",
                    cfg=oidc_config,
                )
