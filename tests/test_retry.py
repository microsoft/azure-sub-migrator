"""Tests for tenova.retry — Azure SDK retry helpers."""

from __future__ import annotations

import pytest

from tenova.retry import _is_retryable, azure_retry, retry_call

# ── Fake Azure exceptions ────────────────────────────────────────────

class FakeHttpResponseError(Exception):
    """Mimic azure.core.exceptions.HttpResponseError."""
    def __init__(self, status_code: int | None = None):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


class FakeServiceRequestError(Exception):
    """Mimic azure.core.exceptions.ServiceRequestError."""


class FakeServiceResponseError(Exception):
    """Mimic azure.core.exceptions.ServiceResponseError."""


class FakeClientAuthenticationError(Exception):
    """Mimic azure.core.exceptions.ClientAuthenticationError."""


# Monkey-patch real types for isinstance checks
@pytest.fixture(autouse=True)
def _patch_azure_types(monkeypatch):
    """Patch tenova.retry so isinstance checks match our fakes."""
    import tenova.retry as mod
    monkeypatch.setattr(mod, "HttpResponseError", FakeHttpResponseError)
    monkeypatch.setattr(mod, "ServiceRequestError", FakeServiceRequestError)
    monkeypatch.setattr(mod, "ServiceResponseError", FakeServiceResponseError)
    monkeypatch.setattr(mod, "ClientAuthenticationError", FakeClientAuthenticationError)


# ── _is_retryable tests ─────────────────────────────────────────────

class TestIsRetryable:
    def test_429_is_retryable(self):
        assert _is_retryable(FakeHttpResponseError(429)) is True

    def test_500_is_retryable(self):
        assert _is_retryable(FakeHttpResponseError(500)) is True

    def test_503_is_retryable(self):
        assert _is_retryable(FakeHttpResponseError(503)) is True

    def test_404_is_not_retryable(self):
        assert _is_retryable(FakeHttpResponseError(404)) is False

    def test_400_is_not_retryable(self):
        assert _is_retryable(FakeHttpResponseError(400)) is False

    def test_service_request_error_is_retryable(self):
        assert _is_retryable(FakeServiceRequestError()) is True

    def test_service_response_error_is_retryable(self):
        assert _is_retryable(FakeServiceResponseError()) is True

    def test_auth_error_is_not_retryable(self):
        assert _is_retryable(FakeClientAuthenticationError()) is False

    def test_generic_error_is_not_retryable(self):
        assert _is_retryable(ValueError("oops")) is False

    def test_wrapped_429_is_retryable(self):
        """Errors wrapped in a cause chain are still retried."""
        cause = FakeHttpResponseError(429)
        wrapper = RuntimeError("wrapped")
        wrapper.__cause__ = cause
        assert _is_retryable(wrapper) is True

    def test_wrapped_auth_error_is_not_retryable(self):
        """Auth errors in the cause chain are not retried."""
        cause = FakeClientAuthenticationError()
        wrapper = RuntimeError("wrapped")
        wrapper.__cause__ = cause
        assert _is_retryable(wrapper) is False


# ── azure_retry decorator tests ─────────────────────────────────────

class TestAzureRetry:
    def test_succeeds_without_retry(self):
        call_count = 0

        @azure_retry
        def good():
            nonlocal call_count
            call_count += 1
            return 42

        assert good() == 42
        assert call_count == 1

    def test_retries_on_transient_then_succeeds(self):
        call_count = 0

        @azure_retry
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise FakeHttpResponseError(429)
            return "ok"

        assert flaky() == "ok"
        assert call_count == 3

    def test_gives_up_after_max_attempts(self):
        @azure_retry
        def always_fails():
            raise FakeHttpResponseError(500)

        with pytest.raises(FakeHttpResponseError):
            always_fails()

    def test_does_not_retry_auth_error(self):
        call_count = 0

        @azure_retry
        def auth_fail():
            nonlocal call_count
            call_count += 1
            raise FakeClientAuthenticationError()

        with pytest.raises(FakeClientAuthenticationError):
            auth_fail()

        assert call_count == 1

    def test_does_not_retry_value_error(self):
        call_count = 0

        @azure_retry
        def bad_input():
            nonlocal call_count
            call_count += 1
            raise ValueError("bad")

        with pytest.raises(ValueError):
            bad_input()

        assert call_count == 1


# ── retry_call tests ────────────────────────────────────────────────

class TestRetryCall:
    def test_simple_call(self):
        assert retry_call(lambda: 99) == 99

    def test_retries_transient(self):
        counter = {"n": 0}

        def flaky():
            counter["n"] += 1
            if counter["n"] < 2:
                raise FakeServiceRequestError()
            return "done"

        assert retry_call(flaky) == "done"
        assert counter["n"] == 2
