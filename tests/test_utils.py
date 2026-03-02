from typing import Any, Dict
from unittest.mock import patch

import httpx
import jwt as pyjwt
import pytest

from py_oidc_auth import IDToken, OIDCAuth
from py_oidc_auth.exceptions import InvalidRequest
from py_oidc_auth.schema import UserInfo
from py_oidc_auth.utils import (
    OIDCConfig,
    get_userinfo,
    get_username,
    process_payload,
    query_user,
    string_to_dict,
    token_field_matches,
)

from .conftest import CLIENT_ID, CLIENT_SECRET, DISCOVERY_URL


def _make_token(**overrides: Any) -> IDToken:
    defaults = {
        "sub": "sub-12345",
        "iss": "https://kc.example.com/realms/test",
    }
    defaults.update(overrides)
    return IDToken(**defaults)


def _make_cfg() -> OIDCConfig:
    """Minimal OIDCConfig with a fake userinfo_endpoint."""
    cfg = OIDCConfig(client_id="test")
    cfg._oidc_overview = {
        "userinfo_endpoint": "https://kc.example.com/userinfo",
    }
    return cfg


class TestQueryUser:

    @pytest.mark.asyncio
    async def test_direct_extraction(self) -> None:
        """Token data has all required fields — no fallback needed."""
        result = await query_user(
            {
                "preferred_username": "jane",
                "email": "jane@example.com",
                "given_name": "Jane",
                "family_name": "Doe",
            },
            authorization="Bearer xyz",
            cfg=_make_cfg(),
        )
        assert isinstance(result, UserInfo)
        assert result.username == "jane"
        assert result.email == "jane@example.com"
        assert result.first_name == "Jane"
        assert result.last_name == "Doe"

    @pytest.mark.asyncio
    async def test_falls_back_to_userinfo_endpoint(self) -> None:
        """Incomplete token data triggers a userinfo fetch."""
        userinfo_response = {
            "preferred_username": "from_endpoint",
            "email": "ep@example.com",
            "given_name": "Endpoint",
            "family_name": "User",
        }
        with patch(
            "py_oidc_auth.utils.oidc_request",
            return_value=userinfo_response,
        ) as mock_req:
            result = await query_user(
                {},  # empty → ValidationError → fallback
                authorization="Bearer xyz",
                cfg=_make_cfg(),
            )
        mock_req.assert_called_once()
        assert result.username == "from_endpoint"

    @pytest.mark.asyncio
    async def test_fallback_also_fails_raises_404(self) -> None:
        """Both token data and userinfo endpoint fail → InvalidRequest 404."""
        bad_response = {"sub": "123"}  # not enough for UserInfo
        with patch(
            "py_oidc_auth.utils.oidc_request",
            return_value=bad_response,
        ):
            with pytest.raises(InvalidRequest) as exc_info:
                await query_user({}, authorization="Bearer xyz", cfg=_make_cfg())
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_upstream_error_propagates(self) -> None:
        """oidc_request failure propagates as InvalidRequest."""
        with patch(
            "py_oidc_auth.utils.oidc_request",
            side_effect=InvalidRequest(502, "upstream down"),
        ):
            with pytest.raises(InvalidRequest) as exc_info:
                await query_user({}, authorization="Bearer xyz", cfg=_make_cfg())
        assert exc_info.value.status_code == 502


class TestGetUsername:

    @pytest.mark.asyncio
    async def test_none_user_returns_none(self) -> None:
        result = await get_username(None, {}, _make_cfg())
        assert result is None

    @pytest.mark.asyncio
    async def test_preferred_username(self) -> None:
        token = _make_token(preferred_username="jane")
        result = await get_username(token, {}, _make_cfg())
        assert result == "jane"

    @pytest.mark.asyncio
    async def test_username_field(self) -> None:
        """Falls through preferred_username (None) to username."""
        token = _make_token(username="bob")
        result = await get_username(token, {}, _make_cfg())
        assert result == "bob"

    @pytest.mark.asyncio
    async def test_user_name_field(self) -> None:
        """Falls through to user_name."""
        token = _make_token(user_name="charlie")
        result = await get_username(token, {}, _make_cfg())
        assert result == "charlie"

    @pytest.mark.asyncio
    async def test_fallback_to_userinfo_endpoint(self) -> None:
        """No username in token → fetches from userinfo endpoint."""
        token = _make_token()  # no username fields
        header = {"authorization": "Bearer xyz"}

        async def _mock_query_user(
            token_data: Dict, authorization: str, cfg: Any
        ) -> UserInfo:
            return UserInfo(
                username="from_userinfo",
                first_name="First",
                last_name="Last",
                pw_name="from_userinfo",
            )

        with patch("py_oidc_auth.utils.query_user", side_effect=_mock_query_user):
            result = await get_username(token, header, _make_cfg())
        assert result == "from_userinfo"

    @pytest.mark.asyncio
    async def test_fallback_query_user_fails_returns_sub(self) -> None:
        """Userinfo endpoint fails → falls back to sub claim."""
        token = _make_token(sub="sub-fallback-789")
        header = {"authorization": "Bearer xyz"}

        with patch(
            "py_oidc_auth.utils.query_user",
            side_effect=InvalidRequest(502, "fail"),
        ):
            result = await get_username(token, header, _make_cfg())
        assert result == "sub-fallback-789"

    @pytest.mark.asyncio
    async def test_no_authorization_header_returns_sub(self) -> None:
        """No authorization header → skips userinfo, returns sub."""
        token = _make_token(sub="sub-no-auth")
        result = await get_username(token, {}, _make_cfg())
        assert result == "sub-no-auth"

    @pytest.mark.asyncio
    async def test_no_sub_no_username_returns_none(self) -> None:
        """Token with no username fields and no sub → None."""
        token = IDToken(iss="https://example.com")  # no sub, no username
        result = await get_username(token, {}, _make_cfg())
        assert result is None

    @pytest.mark.asyncio
    async def test_prefers_token_over_userinfo(self) -> None:
        """Username in token → userinfo endpoint is never called."""
        token = _make_token(preferred_username="from_token")
        header = {"authorization": "Bearer xyz"}

        with patch("py_oidc_auth.utils.query_user") as mock_query:
            result = await get_username(token, header, _make_cfg())

        assert result == "from_token"
        mock_query.assert_not_called()


class TestMakeOidcRequest:
    """Tests for OIDCAuth.make_oidc_request."""

    @pytest.mark.asyncio
    async def test_missing_endpoint_key(self, oidc_auth: OIDCAuth) -> None:
        from py_oidc_auth.auth_base import InvalidRequest

        with pytest.raises(InvalidRequest) as exc_info:
            await oidc_auth.make_oidc_request("POST", "nonexistent_endpoint")
        assert exc_info.value.status_code == 502

    @pytest.mark.asyncio
    async def test_valid_endpoint_key(
        self, oidc_auth: OIDCAuth, refresh_token: str
    ) -> None:
        data: Dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": CLIENT_ID,
        }
        if CLIENT_SECRET:
            data["client_secret"] = CLIENT_SECRET
        result = await oidc_auth.make_oidc_request(
            "POST", "token_endpoint", data=data
        )
        assert "access_token" in result


class TestIDToken:
    """Tests for the IDToken Pydantic model."""

    def test_extra_fields_preserved(self) -> None:
        token = IDToken(
            sub="123",
            custom_claim="hello",
            nested={"a": 1},
        )
        assert token.sub == "123"
        assert token.model_extra["custom_claim"] == "hello"

    def test_from_real_token(self, access_token: str) -> None:
        payload = pyjwt.decode(access_token, options={"verify_signature": False})
        token = IDToken(**payload)
        assert token.sub is not None
        assert token.iss is not None


class TestOIDCConfig:
    """Tests for OIDCConfig and its lazy discovery fetch."""

    def test_discovery_fetched_lazily(self) -> None:
        cfg = OIDCConfig(
            client_id=CLIENT_ID,
            discovery_url=DISCOVERY_URL,
        )
        # Not fetched yet
        assert cfg._oidc_overview is None
        # Accessing the property triggers fetch
        overview = cfg.oidc_overview
        assert "authorization_endpoint" in overview
        assert "token_endpoint" in overview
        assert "jwks_uri" in overview

    def test_discovery_cached(self) -> None:
        cfg = OIDCConfig(
            client_id=CLIENT_ID,
            discovery_url=DISCOVERY_URL,
        )
        overview1 = cfg.oidc_overview
        overview2 = cfg.oidc_overview
        assert overview1 is overview2

    def test_invalid_url_returns_empty(self) -> None:
        cfg = OIDCConfig(
            client_id="x",
            discovery_url="http://127.0.0.1:1/nonexistent",
            timeout=httpx.Timeout(1),
        )
        assert cfg.oidc_overview == {}

    def test_empty_url_returns_empty(self) -> None:
        cfg = OIDCConfig(client_id="x", discovery_url="")
        assert cfg.oidc_overview == {}


class TestSetRequestHeader:
    """Tests for _set_request_header."""

    def test_with_secret_uses_basic_auth(self) -> None:
        from py_oidc_auth.auth_base import _set_request_header

        data: Dict[str, str] = {}
        header: Dict[str, str] = {}
        _set_request_header("myid", "mysecret", data, header)

        assert header["Content-Type"] == "application/x-www-form-urlencoded"
        assert header["Authorization"].startswith("Basic ")
        assert "client_id" not in data

    def test_without_secret_puts_client_id_in_data(self) -> None:
        from py_oidc_auth.auth_base import _set_request_header

        data: Dict[str, str] = {}
        header: Dict[str, str] = {}
        _set_request_header("myid", None, data, header)

        assert "Authorization" not in header
        assert data["client_id"] == "myid"

    def test_overwrites_existing_content_type(self) -> None:
        from py_oidc_auth.auth_base import _set_request_header

        header: Dict[str, str] = {"Content-Type": "text/html"}
        data: Dict[str, str] = {}
        _set_request_header("myid", None, data, header)
        assert header["Content-Type"] == "application/x-www-form-urlencoded"


class TestStringToDict:
    """Tests for the string_to_dict helper."""

    def test_basic_conversion(self) -> None:
        result = string_to_dict("key1:value1,key2:value2")
        assert result == {"key1": ["value1"], "key2": ["value2"]}

    def test_multiple_values_same_key(self) -> None:
        result = string_to_dict("k:a,k:b,k:c")
        assert result == {"k": ["a", "b", "c"]}

    def test_deduplication(self) -> None:
        result = string_to_dict("k:a,k:a")
        assert result == {"k": ["a"]}

    def test_empty_string(self) -> None:
        result = string_to_dict("")
        assert result == {}

    def test_malformed_entries_ignored(self) -> None:
        result = string_to_dict("good:val,,bad,also:ok")
        assert "good" in result
        assert "also" in result


class TestMisc:
    """Test for "other" functions."""

    def test_process_payload(self) -> None:
        """Processing the payload."""

        payload = {"Foo": "foo", "foo": "bar"}

        assert process_payload(payload, "foo") == "bar"
        assert process_payload(payload, "Foo") == "foo"
        assert process_payload(payload, "foO") == "bar"
        assert process_payload(payload, "foOz") is None


class TestTokenFieldMatches:
    """Tests for token_field_matches."""

    def test_no_claims_always_matches(self) -> None:
        assert token_field_matches("anything", claims=None) is True
        assert token_field_matches("anything", claims={}) is True

    def test_match_against_real_token(self, access_token: str) -> None:
        """Validate claims in a real Keycloak token."""
        # The test user's token should have aud containing the client_id
        decoded = pyjwt.decode(access_token, options={"verify_signature": False})
        # Use a claim we know exists
        if "aud" in decoded:
            aud = decoded["aud"]
            if isinstance(aud, list):
                assert token_field_matches(access_token, claims={"aud": [aud[0]]})

    def test_no_match_returns_false(self, access_token: str) -> None:
        assert (
            token_field_matches(
                access_token,
                claims={"realm_access.roles": ["completely-fake-role-xyz"]},
            )
            is False
        )

    def test_nested_claim_walk(self) -> None:
        """Test dotted path walking into nested dicts."""
        payload = {"realm_access": {"roles": ["admin", "user"]}}
        token = pyjwt.encode(payload, "secret")
        assert token_field_matches(
            token, claims={"realm_access.roles": ["admin"]}
        )
        assert not token_field_matches(
            token, claims={"realm_access.roles": ["superuser"]}
        )


class TestGetUserinfo:
    """Tests for get_userinfo extraction."""

    def test_extracts_standard_fields(self) -> None:
        info = get_userinfo(
            {
                "preferred_username": "jane",
                "email": "jane@example.com",
                "given_name": "Jane",
                "family_name": "Doe",
            }
        )
        assert info["username"] == "jane"
        assert info["email"] == "jane@example.com"
        assert info["first_name"] == "Jane"
        assert info["last_name"] == "Doe"

    def test_hyphenated_keys(self) -> None:
        info = get_userinfo(
            {
                "preferred-username": "bob",
                "given-name": "Bob",
                "family-name": "Smith",
            }
        )
        assert info["username"] == "bob"
        assert info["first_name"] == "Bob"

    def test_fallback_uid(self) -> None:
        info = get_userinfo({"uid": "alice"})
        assert info["username"] == "alice"

    def test_missing_fields(self) -> None:
        info = get_userinfo({})
        assert info["username"] == ""
        assert info["email"] == ""
