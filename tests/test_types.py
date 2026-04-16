"""Tests for _types module: AuthResult, CookieData, Credentials."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from web_auth_bridge._types import AuthResult, CookieData, Credentials


class TestCredentials:
    """Tests for the Credentials dataclass."""

    def test_creation(self) -> None:
        creds = Credentials(username="user", password="pass")
        assert creds.username == "user"
        assert creds.password == "pass"
        assert creds.extra == {}

    def test_extra_fields(self) -> None:
        creds = Credentials(username="u", password="p", extra={"mfa": "123456"})
        assert creds.extra["mfa"] == "123456"

    def test_frozen(self) -> None:
        creds = Credentials(username="u", password="p")
        with pytest.raises(AttributeError):
            creds.username = "other"  # ty: ignore[invalid-assignment]


class TestCookieData:
    """Tests for the CookieData dataclass."""

    def test_to_playwright_dict(self, sample_cookie: CookieData) -> None:
        d = sample_cookie.to_playwright_dict()
        assert d["name"] == "session_id"
        assert d["value"] == "abc123"
        assert d["domain"] == ".example.com"
        assert d["secure"] is True
        assert d["httpOnly"] is True
        assert "expires" not in d

    def test_to_playwright_dict_with_expires(self) -> None:
        cookie = CookieData(name="c", value="v", domain="d", expires=1700000000.0)
        d = cookie.to_playwright_dict()
        assert d["expires"] == 1700000000.0

    def test_from_playwright_dict(self) -> None:
        data = {
            "name": "test",
            "value": "val",
            "domain": ".example.com",
            "path": "/api",
            "secure": True,
            "httpOnly": False,
            "sameSite": "Strict",
            "expires": 1700000000.0,
        }
        cookie = CookieData.from_playwright_dict(data)
        assert cookie.name == "test"
        assert cookie.value == "val"
        assert cookie.path == "/api"
        assert cookie.same_site == "Strict"
        assert cookie.expires == 1700000000.0

    def test_roundtrip(self, sample_cookie: CookieData) -> None:
        pw_dict = sample_cookie.to_playwright_dict()
        restored = CookieData.from_playwright_dict(pw_dict)
        assert restored.name == sample_cookie.name
        assert restored.value == sample_cookie.value
        assert restored.domain == sample_cookie.domain


class TestAuthResult:
    """Tests for the AuthResult dataclass."""

    def test_is_expired_no_expiry(self) -> None:
        result = AuthResult()
        assert result.is_expired is False

    def test_is_expired_future(self) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) + timedelta(hours=1))
        assert result.is_expired is False

    def test_is_expired_past(self) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) - timedelta(hours=1))
        assert result.is_expired is True

    def test_to_dict_and_from_dict(self, sample_auth_result: AuthResult) -> None:
        d = sample_auth_result.to_dict()
        restored = AuthResult.from_dict(d)
        assert len(restored.cookies) == 1
        assert restored.cookies[0].name == "session_id"
        assert restored.tokens["jwt_web"] == sample_auth_result.tokens["jwt_web"]
        assert restored.local_storage["user_id"] == "12345"

    def test_from_dict_empty(self) -> None:
        result = AuthResult.from_dict({})
        assert result.cookies == []
        assert result.tokens == {}
        assert result.local_storage == {}

    def test_from_dict_with_expiry(self) -> None:
        expires = datetime.now(UTC) + timedelta(hours=2)
        d = {"expires_at": expires.isoformat(), "created_at": expires.isoformat()}
        result = AuthResult.from_dict(d)
        assert result.expires_at is not None
        assert result.is_expired is False
