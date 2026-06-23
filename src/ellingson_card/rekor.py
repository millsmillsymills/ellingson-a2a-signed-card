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
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

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
        the returned entry's own ``logIndex`` does not match the requested index.
        That last check is a self-consistency check that the server returned the
        entry we asked for -- the value is server-echoed, not a cryptographic
        inclusion proof or SET; binding to the signature (``entry_binds``) is the
        real control.

    Raises:
        urllib.error.URLError: On network failure (the verifier then fails closed
            because no result is returned).
    """
    url = f"{base_url}/api/v1/log/entries?logIndex={int(log_index)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
            if response.status != 200:
                logger.warning("Rekor returned HTTP %s for logIndex=%s", response.status, log_index)
                return None
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            logger.debug("no Rekor entry at logIndex=%s (HTTP 404)", log_index)
            return None
        raise
    try:
        payload = json.loads(raw)
    except ValueError:
        logger.warning("Rekor response for logIndex=%s is not valid JSON", log_index)
        return None
    return _decode_body(payload, int(log_index))


def _decode_body(payload: Any, log_index: int) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not payload:
        logger.debug("Rekor payload for logIndex=%s is not a non-empty object", log_index)
        return None
    entry = next(iter(payload.values()))
    if not isinstance(entry, dict):
        logger.debug("Rekor entry for logIndex=%s is not an object", log_index)
        return None
    if entry.get("logIndex") != log_index:
        logger.warning(
            "Rekor entry reports logIndex=%r but %s was requested",
            entry.get("logIndex"),
            log_index,
        )
        return None
    raw_body = entry.get("body")
    if not isinstance(raw_body, str):
        logger.debug("Rekor entry body for logIndex=%s is missing or not a string", log_index)
        return None
    try:
        body = json.loads(base64.b64decode(raw_body))
    except (binascii.Error, ValueError):
        logger.warning("Rekor entry body for logIndex=%s is not valid base64 JSON", log_index)
        return None
    if not isinstance(body, dict):
        logger.debug("Rekor entry body for logIndex=%s decoded to a non-object", log_index)
        return None
    return body


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

    Two things are pinned. The ``apiVersion`` is rejected if unknown because the
    ``hashedrekord`` spec layout differs across versions: a 0.0.2 body nests under
    ``spec.hashedRekordV002``, so reading it with 0.0.1 field paths fails closed
    (every lookup misses, so the entry simply fails to bind) -- pinning keeps a
    future schema from ever being parsed under stale paths. The hash algorithm is
    pinned to ``sha256`` because hashedrekord 0.0.1 itself also accepts sha384 and
    sha512; without the pin, a same-version digest-algorithm swap is the real
    misbind risk.
    """
    if body.get("kind") != "hashedrekord":
        logger.debug("Rekor entry kind is %r, not hashedrekord", body.get("kind"))
        return False
    if body.get("apiVersion") != SUPPORTED_HASHEDREKORD_APIVERSION:
        logger.warning(
            "Rekor entry apiVersion is %r, not the supported %s",
            body.get("apiVersion"),
            SUPPORTED_HASHEDREKORD_APIVERSION,
        )
        return False
    spec = body.get("spec")
    if not isinstance(spec, dict):
        logger.debug("Rekor entry spec is not an object")
        return False
    if _dig(spec, "data", "hash", "algorithm") != EXPECTED_HASH_ALGORITHM:
        logger.debug(
            "Rekor entry hash algorithm is %r, not %s",
            _dig(spec, "data", "hash", "algorithm"),
            EXPECTED_HASH_ALGORITHM,
        )
        return False
    if _dig(spec, "data", "hash", "value") != artifact_sha256_hex:
        logger.warning(
            "Rekor entry artifact digest does not match the signature under verification"
        )
        return False
    return _signature_binds(spec, signature_der)


def _signature_binds(spec: dict[str, Any], signature_der: bytes) -> bool:
    logged_sig = _dig(spec, "signature", "content")
    if not isinstance(logged_sig, str):
        logger.debug("Rekor entry signature content is missing or not a string")
        return False
    try:
        decoded_sig = base64.b64decode(logged_sig)
    except (binascii.Error, ValueError):
        logger.debug("Rekor entry signature content is not valid base64")
        return False
    if decoded_sig != signature_der:
        logger.warning("Rekor entry signature does not match the signature under verification")
        return False
    return True


def _dig(mapping: dict[str, Any], *keys: str) -> Any:
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
