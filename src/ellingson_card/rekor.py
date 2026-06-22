"""Rekor transparency-log inclusion check.

Confirms a signature's Rekor log entry actually exists, rather than assuming it
from the presence of a log index in the signature header. Queries the public
Rekor v1 REST API directly so we do not depend on Sigstore's private client.
"""

from __future__ import annotations

import urllib.error
import urllib.request

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"


def rekor_entry_exists(
    log_index: int,
    *,
    base_url: str = DEFAULT_REKOR_URL,
    timeout: float = 10.0,
) -> bool:
    """Return whether a Rekor entry exists at ``log_index``.

    Args:
        log_index: The transparency-log index recorded in the signature header.
        base_url: The Rekor instance base URL.
        timeout: HTTP timeout in seconds.

    Returns:
        True if the entry is present (HTTP 200), False if absent (HTTP 404).

    Raises:
        urllib.error.URLError: On network failure (the verifier then fails closed
            because no result is returned).
    """
    url = f"{base_url}/api/v1/log/entries?logIndex={int(log_index)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            return response.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise
