from unittest.mock import MagicMock, patch
import pytest
from utils.oauth_agentrouter import (
	AgentRouterOAuthClient,
	extract_code_from_location,
	build_github_cookies,
)


def test_build_github_cookies():
	cookies = build_github_cookies("test_user_session_token")
	assert cookies["user_session"] == "test_user_session_token"
	assert cookies["logged_in"] == "yes"
	assert cookies["__Host-user_session_same_site"] == "test_user_session_token"


def test_extract_code_from_location():
	loc = "https://agentrouter.org/api/oauth/github?code=abc123xyz&state=state456"
	assert extract_code_from_location(loc) == "abc123xyz"

	# Login redirect indicates invalid session
	login_loc = "https://github.com/login"
	assert extract_code_from_location(login_loc) is None


def test_fetch_oauth_state(monkeypatch):
	oauth = AgentRouterOAuthClient(domain="https://agentrouter.org")
	mock_client = MagicMock()
	mock_resp = MagicMock()
	mock_resp.status_code = 200
	mock_resp.json.return_value = {"success": True, "data": "state_token_123"}
	mock_client.get.return_value = mock_resp

	state = oauth.fetch_oauth_state(mock_client)
	assert state == "state_token_123"


def test_authorize_github_from_meta_refresh():
	oauth = AgentRouterOAuthClient(domain="https://agentrouter.org")
	mock_resp = MagicMock()
	mock_resp.status_code = 200
	mock_resp.headers = {}
	mock_resp.text = '<html><head><title>OAuth application authorized</title><meta http-equiv="refresh" content="0;url=https://agentrouter.org/api/oauth/github?code=secret_code_789&state=state123"></head></html>'

	with patch("httpx.Client.get", return_value=mock_resp):
		code = oauth.authorize_github("test_session", "state123")
		assert code == "secret_code_789"


def test_callback_login_success():
	oauth = AgentRouterOAuthClient(domain="https://agentrouter.org")
	mock_client = MagicMock()
	mock_resp = MagicMock()
	mock_resp.status_code = 200
	mock_resp.json.return_value = {
		"success": True,
		"data": {"id": 100, "username": "testuser", "quota": 50000000, "checked_in": True},
		"message": "",
	}
	mock_client.get.return_value = mock_resp

	success, data, checked_in, msg = oauth.callback_login(
		mock_client, provider="github", code="code123", state="state123"
	)
	assert success is True
	assert checked_in is True
	assert data["id"] == 100
	assert data["quota"] == 50000000
