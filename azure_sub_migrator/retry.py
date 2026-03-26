# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Retry helpers for transient Azure SDK failures.

Azure Resource Manager commonly returns 429 (throttled) and occasional
5xx errors.  The decorator provided here wraps any function with
exponential back-off so callers don't have to implement retry logic
themselves.

Usage::

    from azure_sub_migrator.retry import azure_retry

    @azure_retry
    def _list_resources(...):
        ...
"""

from __future__ import annotations

import logging
from typing import Any

from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ServiceRequestError,
    ServiceResponseError,
)
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger("azure_sub_migrator.retry")


def _is_retryable(exc: BaseException) -> bool:
    """Return True if *exc* is a transient Azure SDK error worth retrying.

    Also checks the exception cause chain so wrapped errors (e.g.,
    ``RBACError`` wrapping an ``HttpResponseError``) are retried.
    """
    current: BaseException | None = exc
    while current is not None:
        # Network-level transient errors
        if isinstance(current, (ServiceRequestError, ServiceResponseError)):
            return True

        # HTTP-level errors: retry on 429 (throttled) and 5xx (server errors)
        if isinstance(current, HttpResponseError):
            if current.status_code == 429:
                return True
            if current.status_code is not None and current.status_code >= 500:
                return True

        # Never retry auth failures — they won't self-heal
        if isinstance(current, ClientAuthenticationError):
            return False

        current = current.__cause__

    return False


azure_retry = retry(
    retry=retry_if_exception(_is_retryable),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=1, max=30),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
"""Decorator: retry on transient Azure errors (429, 5xx, network).

Attempts up to 5 times with exponential back-off (1s → 2s → 4s → …, max 30s).
Auth errors are never retried.
"""


def retry_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Call *fn* with retry on transient Azure errors.

    Use this for one-off wrapping of SDK calls inside existing
    try/except blocks::

        result = retry_call(client.resources.list)
    """
    return azure_retry(fn)(*args, **kwargs)
