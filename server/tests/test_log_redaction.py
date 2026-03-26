"""Tests for logging.py — secret redaction in structured log events."""

from authgent_server.logging import _NEVER_LOG_KEYS, _redact_sensitive_values


class TestNeverLogKeysRedaction:
    """Keys in _NEVER_LOG_KEYS must always be replaced with **REDACTED**."""

    def test_client_secret_redacted(self):
        event = {"event": "registered", "client_secret": "sec_abc123xyz"}
        result = _redact_sensitive_values(None, "info", event)
        assert result["client_secret"] == "**REDACTED**"

    def test_access_token_redacted(self):
        event = {"event": "issued", "access_token": "eyJhbGciOi..."}
        result = _redact_sensitive_values(None, "info", event)
        assert result["access_token"] == "**REDACTED**"

    def test_refresh_token_redacted(self):
        event = {"event": "rotated", "refresh_token": "tok_abc123"}
        result = _redact_sensitive_values(None, "info", event)
        assert result["refresh_token"] == "**REDACTED**"

    def test_password_redacted(self):
        event = {"event": "login", "password": "hunter2"}
        result = _redact_sensitive_values(None, "info", event)
        assert result["password"] == "**REDACTED**"

    def test_subject_token_redacted(self):
        event = {"event": "exchange", "subject_token": "eyJ..."}
        result = _redact_sensitive_values(None, "info", event)
        assert result["subject_token"] == "**REDACTED**"

    def test_actor_token_redacted(self):
        event = {"event": "exchange", "actor_token": "eyJ..."}
        result = _redact_sensitive_values(None, "info", event)
        assert result["actor_token"] == "**REDACTED**"

    def test_authorization_header_redacted(self):
        event = {"event": "request", "authorization": "Bearer eyJ..."}
        result = _redact_sensitive_values(None, "info", event)
        assert result["authorization"] == "**REDACTED**"

    def test_code_verifier_redacted(self):
        event = {"event": "pkce", "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
        result = _redact_sensitive_values(None, "info", event)
        assert result["code_verifier"] == "**REDACTED**"

    def test_private_key_pem_redacted(self):
        event = {"event": "keygen", "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n..."}
        result = _redact_sensitive_values(None, "info", event)
        assert result["private_key_pem"] == "**REDACTED**"

    def test_all_never_log_keys_covered(self):
        """Verify every key in _NEVER_LOG_KEYS is actually redacted."""
        for key in _NEVER_LOG_KEYS:
            event = {"event": "test", key: "sensitive_value_12345"}
            result = _redact_sensitive_values(None, "info", event)
            assert result[key] == "**REDACTED**", f"Key '{key}' was not redacted"


class TestPatternRedaction:
    """Regex patterns catch secrets embedded in string values."""

    def test_bearer_token_in_string(self):
        event = {"event": "log", "msg": "Got Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"}
        result = _redact_sensitive_values(None, "info", event)
        assert "eyJhbGci" not in result["msg"]
        assert "**REDACTED**" in result["msg"]

    def test_basic_auth_in_string(self):
        event = {"event": "log", "msg": "Header: Basic dXNlcjpwYXNz"}
        result = _redact_sensitive_values(None, "info", event)
        assert "dXNlcjpwYXNz" not in result["msg"]

    def test_dpop_token_in_string(self):
        event = {"event": "log", "msg": "DPoP eyJhbGciOiJFUzI1NiJ9.payload.sig"}
        result = _redact_sensitive_values(None, "info", event)
        assert "eyJhbGci" not in result["msg"]

    def test_query_string_secrets_redacted(self):
        event = {"event": "log", "msg": "client_secret=sec_abc123&other=value"}
        result = _redact_sensitive_values(None, "info", event)
        assert "sec_abc123" not in result["msg"]
        assert "client_secret=**REDACTED**" in result["msg"]

    def test_token_in_query_string(self):
        event = {"event": "log", "msg": "token=eyJhbGciOi...&grant_type=refresh"}
        result = _redact_sensitive_values(None, "info", event)
        assert "eyJhbGci" not in result["msg"]


class TestNonSensitiveFieldsPreserved:
    """Non-sensitive fields must pass through unchanged."""

    def test_event_name_preserved(self):
        event = {"event": "client_registered", "client_id": "agnt_abc", "client_name": "test"}
        result = _redact_sensitive_values(None, "info", event)
        assert result["event"] == "client_registered"
        assert result["client_id"] == "agnt_abc"
        assert result["client_name"] == "test"

    def test_numeric_values_preserved(self):
        event = {"event": "token_issued", "expires_in": 900, "status_code": 200}
        result = _redact_sensitive_values(None, "info", event)
        assert result["expires_in"] == 900
        assert result["status_code"] == 200

    def test_mixed_sensitive_and_safe(self):
        """Sensitive keys redacted, safe keys preserved in same event."""
        event = {
            "event": "token_issued",
            "client_id": "agnt_test",
            "client_secret": "sec_secret_value",
            "scope": "read write",
            "access_token": "eyJ...",
        }
        result = _redact_sensitive_values(None, "info", event)
        assert result["client_id"] == "agnt_test"
        assert result["scope"] == "read write"
        assert result["client_secret"] == "**REDACTED**"
        assert result["access_token"] == "**REDACTED**"
