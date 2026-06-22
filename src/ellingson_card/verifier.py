"""Fail-closed, identity-pinned Agent Card verifier.

Verification order: signature presence -> JWS signature -> identity pinning ->
freshness -> Rekor inclusion. Each rejection raises a distinct error subclass.
Identity pinning is on by default; an unpinned verifier would accept any
Sigstore-signed card, which is nearly useless.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ellingson_card.errors import (
    BadSignature,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
)
from ellingson_card.keys import identity_from_cert, x5c_to_cert
from ellingson_card.rekor import rekor_entry_exists
from ellingson_card.signer import signing_input

_COORD_BYTES = 32

RekorChecker = Callable[[int], bool]


def default_rekor_checker(log_index: int) -> bool:
    """Confirm a Rekor entry exists for ``log_index`` against the public instance."""
    return rekor_entry_exists(log_index)


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of a successful verification."""

    identity: str
    rekor_log_index: int | None
    valid: bool = True


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_jws(card: dict[str, Any], signature: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    try:
        cert = x5c_to_cert(signature["header"]["x5c"][0])
        public_key = cert.public_key()
        raw = _b64url_decode(signature["signature"])
        der = encode_dss_signature(
            int.from_bytes(raw[:_COORD_BYTES], "big"),
            int.from_bytes(raw[_COORD_BYTES:], "big"),
        )
        message = signing_input(card, signature["protected"])
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise BadSignature(f"malformed signature: {exc}") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise BadSignature("signing certificate is not an EC key")
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise BadSignature("signature does not match canonical card") from exc
    return public_key


def _check_freshness(cert_x5c: str, max_age: timedelta | None) -> None:
    cert = x5c_to_cert(cert_x5c)
    now = datetime.now(UTC)
    if now > cert.not_valid_after_utc:
        raise CardExpired(f"signing certificate expired at {cert.not_valid_after_utc.isoformat()}")
    if max_age is not None and now - cert.not_valid_before_utc > max_age:
        raise CardExpired(f"signature older than max age {max_age}")


def verify_card(
    card_json: dict[str, Any],
    *,
    expected_identity: str,
    require_rekor: bool = True,
    rekor_checker: RekorChecker = default_rekor_checker,
    max_age: timedelta | None = None,
) -> VerifyResult:
    """Verify a signed Agent Card, failing closed with a distinct error per control.

    Args:
        card_json: The served, signed card as a dict.
        expected_identity: The certificate URI SAN identity to pin.
        require_rekor: If true, a confirmed Rekor entry is mandatory.
        rekor_checker: Predicate confirming a Rekor entry exists for a log index.
        max_age: If set, reject signatures whose cert is older than this.

    Returns:
        A ``VerifyResult`` on success.

    Raises:
        MissingSignature, BadSignature, IdentityMismatch, CardExpired,
        MissingRekorEntry: On the corresponding failure.
    """
    signatures = card_json.get("signatures")
    if not signatures:
        raise MissingSignature("card has no signatures")
    signature = signatures[0]

    _verify_jws(card_json, signature)

    cert = x5c_to_cert(signature["header"]["x5c"][0])
    identity = identity_from_cert(cert)
    if identity != expected_identity:
        raise IdentityMismatch(f"expected identity {expected_identity!r}, got {identity!r}")

    _check_freshness(signature["header"]["x5c"][0], max_age)

    rekor_log_index = signature["header"].get("rekorLogIndex")
    if require_rekor and not (rekor_log_index is not None and rekor_checker(rekor_log_index)):
        raise MissingRekorEntry("no confirmed Rekor transparency-log entry")

    return VerifyResult(identity=identity, rekor_log_index=rekor_log_index)
