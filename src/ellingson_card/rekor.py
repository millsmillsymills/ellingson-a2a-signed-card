"""Rekor transparency-log inclusion check, bound to the signature being verified.

Confirming an entry merely *exists* at a log index is too weak: an attacker who
already holds one validly logged signature could paste any real index into a
forged card's header and pass. So this module fetches the entry body and binds it
to the artifact hash and signature bytes under verification — the index must
point at a ``hashedrekord`` whose logged signature and artifact digest match the
signature we are checking. Queries the public Rekor v1 REST API directly so we do
not depend on Sigstore's private client.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.error
import urllib.request
from typing import Any

DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

SUPPORTED_HASHEDREKORD_APIVERSION = "0.0.1"
EXPECTED_HASH_ALGORITHM = "sha256"


def fetch_entry_body(
    log_index: int,
    *,
    base_url: str = DEFAULT_REKOR_URL,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Fetch and decode the Rekor entry body at ``log_index``.

    Args:
        log_index: The transparency-log index recorded in the signature header.
        base_url: The Rekor instance base URL.
        timeout: HTTP timeout in seconds.

    Returns:
        The decoded entry body (a ``hashedrekord`` dict) if present, or ``None``
        if no entry exists at the index (HTTP 404), the response is malformed, or
        the returned entry's own ``logIndex`` does not match the requested index
        (so the authenticated index, not just the binding, points at this entry).

    Raises:
        urllib.error.URLError: On network failure (the verifier then fails closed
            because no result is returned).
    """
    url = f"{base_url}/api/v1/log/entries?logIndex={int(log_index)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            if response.status != 200:
                return None
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    return _decode_body(payload, int(log_index))


def _decode_body(payload: Any, log_index: int) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not payload:
        return None
    entry = next(iter(payload.values()))
    if not isinstance(entry, dict):
        return None
    if entry.get("logIndex") != log_index:
        return None
    raw_body = entry.get("body")
    if not isinstance(raw_body, str):
        return None
    try:
        body = json.loads(base64.b64decode(raw_body))
    except (binascii.Error, ValueError):
        return None
    return body if isinstance(body, dict) else None


def entry_binds(
    body: dict[str, Any],
    *,
    artifact_sha256_hex: str,
    signature_der: bytes,
) -> bool:
    """Return whether a Rekor entry body binds to this artifact and signature.

    The entry must be a ``hashedrekord`` at the supported ``apiVersion`` whose
    logged artifact digest (pinned to ``sha256``) equals ``artifact_sha256_hex``
    and whose logged signature equals ``signature_der``. A mismatch, an
    unsupported schema version, or any structural surprise returns ``False`` so
    the verifier fails closed.

    The ``apiVersion`` is pinned because the ``hashedrekord`` spec field layout
    differs across versions (0.0.1 vs 0.0.2); reading a newer schema with the
    0.0.1 field paths would silently misbind, so an unknown version is rejected.
    """
    if body.get("kind") != "hashedrekord":
        return False
    if body.get("apiVersion") != SUPPORTED_HASHEDREKORD_APIVERSION:
        return False
    spec = body.get("spec")
    if not isinstance(spec, dict):
        return False
    if _dig(spec, "data", "hash", "algorithm") != EXPECTED_HASH_ALGORITHM:
        return False
    logged_hash = _dig(spec, "data", "hash", "value")
    if logged_hash != artifact_sha256_hex:
        return False
    logged_sig = _dig(spec, "signature", "content")
    if not isinstance(logged_sig, str):
        return False
    try:
        return base64.b64decode(logged_sig) == signature_der
    except (binascii.Error, ValueError):
        return False


def _dig(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
