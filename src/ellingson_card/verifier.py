"""Fail-closed, identity-pinned Agent Card verifier.

Verification order: signature presence -> JWS signature -> identity pinning ->
freshness -> Rekor inclusion bound to this signature. Each rejection raises a
distinct error subclass. Identity pinning is on by default; an unpinned verifier
would accept any Sigstore-signed card, which is nearly useless.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
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
    UntrustedCertificate,
)
from ellingson_card.keys import identity_from_cert, x5c_to_cert
from ellingson_card.rekor import entry_binds, fetch_entry_body
from ellingson_card.signer import signing_input
from ellingson_card.trust import TrustRoot, oidc_issuer, verify_chain

logger = logging.getLogger(__name__)

_COORD_BYTES = 32

RekorChecker = Callable[[int, str, bytes], bool]


def default_rekor_checker(log_index: int, artifact_sha256_hex: str, signature_der: bytes) -> bool:
    """Confirm a Rekor entry at ``log_index`` binds to this artifact and signature."""
    body = fetch_entry_body(log_index)
    if body is None:
        logger.debug("no usable Rekor entry at logIndex=%s (absent or unreachable)", log_index)
        return False
    if not entry_binds(body, artifact_sha256_hex=artifact_sha256_hex, signature_der=signature_der):
        logger.warning("Rekor entry at logIndex=%s does not bind to this signature", log_index)
        return False
    return True


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of a successful verification."""

    identity: str
    rekor_log_index: int | None
    valid: bool = True


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _valid_log_index(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _load_cert(signature: dict[str, Any]) -> x509.Certificate:
    try:
        return x5c_to_cert(signature["header"]["x5c"][0])
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise BadSignature(f"malformed signing certificate: {exc}") from exc


def _verify_jws(
    card: dict[str, Any], signature: dict[str, Any], cert: x509.Certificate
) -> tuple[bytes, bytes]:
    try:
        raw = _b64url_decode(signature["signature"])
        signature_der = encode_dss_signature(
            int.from_bytes(raw[:_COORD_BYTES], "big"),
            int.from_bytes(raw[_COORD_BYTES:], "big"),
        )
        message = signing_input(card, signature["protected"])
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise BadSignature(f"malformed signature: {exc}") from exc
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise BadSignature("signing certificate is not an EC key")
    try:
        public_key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise BadSignature("signature does not match canonical card") from exc
    return signature_der, message


def _check_freshness(cert: x509.Certificate, max_age: timedelta | None) -> None:
    now = datetime.now(UTC)
    if now > cert.not_valid_after_utc:
        raise CardExpired(f"signing certificate expired at {cert.not_valid_after_utc.isoformat()}")
    if max_age is not None and now - cert.not_valid_before_utc > max_age:
        raise CardExpired(f"signature older than max age {max_age}")


def _intermediates(signature: dict[str, Any]) -> list[x509.Certificate]:
    try:
        return [x5c_to_cert(entry) for entry in signature["header"]["x5c"][1:]]
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise BadSignature(f"malformed x5c chain: {exc}") from exc


def _enforce_trust(
    signature: dict[str, Any],
    cert: x509.Certificate,
    trust_root: TrustRoot,
    expected_oidc_issuer: str,
) -> None:
    verify_chain(cert, _intermediates(signature), trust_root, at_time=datetime.now(UTC))
    issuer = oidc_issuer(cert)
    if issuer != expected_oidc_issuer:
        raise UntrustedCertificate(f"expected OIDC issuer {expected_oidc_issuer!r}, got {issuer!r}")


def verify_card(
    card_json: dict[str, Any],
    *,
    expected_identity: str,
    require_rekor: bool = True,
    rekor_checker: RekorChecker = default_rekor_checker,
    max_age: timedelta | None = None,
    trust_root: TrustRoot | None = None,
    expected_oidc_issuer: str | None = None,
) -> VerifyResult:
    """Verify a signed Agent Card, failing closed with a distinct error per control.

    Args:
        card_json: The served, signed card as a dict.
        expected_identity: The certificate URI SAN identity to pin.
        require_rekor: If true, a Rekor entry bound to this signature is mandatory.
        rekor_checker: Predicate confirming a Rekor entry at a log index binds to
            the artifact digest and DER signature being verified.
        max_age: If set, reject signatures whose cert is older than this.
        trust_root: If set, cryptographically anchor trust by chaining the leaf
            to a trusted Fulcio root; a self-signed cert is then rejected. When
            absent, the hermetic self-signed-friendly path is kept unchanged.
        expected_oidc_issuer: Required whenever ``trust_root`` is set; the Fulcio
            OIDC-issuer extension must equal this value. Issuer pinning is the
            central control of the anchored path, so omitting it is rejected
            rather than silently anchoring the chain alone.

    Returns:
        A ``VerifyResult`` on success.

    Raises:
        ValueError: If ``trust_root`` is set without ``expected_oidc_issuer``.
        MissingSignature, BadSignature, IdentityMismatch, CardExpired,
        UntrustedCertificate, MissingRekorEntry: On the corresponding failure.
    """
    signatures = card_json.get("signatures")
    if not signatures:
        raise MissingSignature("card has no signatures")
    if not isinstance(signatures, list) or not isinstance(signatures[0], dict):
        raise BadSignature("card signatures must be a non-empty array of objects")
    signature = signatures[0]

    cert = _load_cert(signature)
    signature_der, message = _verify_jws(card_json, signature, cert)

    identity = identity_from_cert(cert)
    if identity != expected_identity:
        raise IdentityMismatch(f"expected identity {expected_identity!r}, got {identity!r}")

    _check_freshness(cert, max_age)

    if trust_root is not None:
        if expected_oidc_issuer is None:
            raise ValueError(
                "expected_oidc_issuer is required when trust_root is set: issuer "
                "pinning is the central control of the anchored path"
            )
        _enforce_trust(signature, cert, trust_root, expected_oidc_issuer)

    rekor_log_index = signature["header"].get("rekorLogIndex")
    if require_rekor:
        artifact_hex = hashlib.sha256(message).hexdigest()
        if not _valid_log_index(rekor_log_index) or not rekor_checker(
            rekor_log_index, artifact_hex, signature_der
        ):
            raise MissingRekorEntry("no Rekor transparency-log entry bound to this signature")

    return VerifyResult(identity=identity, rekor_log_index=rekor_log_index)
