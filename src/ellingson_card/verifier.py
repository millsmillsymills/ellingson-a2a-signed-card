"""Fail-closed, identity-pinned Agent Card verifier.

Verification order: signature presence -> JWS signature -> identity pinning ->
freshness -> Sigstore bundle (transparency-log inclusion). Each rejection raises a
distinct error subclass. Identity pinning is on by default; an unpinned verifier
would accept any Sigstore-signed card, which is nearly useless.

A keyless card carries the full Sigstore bundle in its ``sigstoreBundle`` header;
the verifier hands that to Sigstore's offline verifier, which confirms the Fulcio
chain, the SAN identity, and Rekor inclusion from the proof and signed checkpoint
in the bundle -- no log-index REST lookup, so it is correct regardless of which
Rekor version (v1 or v2) signed the card. A card without a bundle is a local,
self-signed card; it is accepted only when ``require_bundle`` is off, in which
case trust rests on identity pinning and optional trust-root anchoring.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding

from ellingson_card.errors import (
    BadSignature,
    BundleVerificationError,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
    UntrustedCertificate,
)
from ellingson_card.keys import identity_from_cert, x5c_to_cert
from ellingson_card.signer import signing_input
from ellingson_card.trust import TrustRoot, oidc_issuer, verify_chain

logger = logging.getLogger(__name__)

_COORD_BYTES = 32
_DER = Encoding.DER


@dataclass(frozen=True)
class VerifyResult:
    """The outcome of a successful verification."""

    identity: str
    rekor_log_index: int | None
    valid: bool = True


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _load_cert(signature: dict[str, Any]) -> x509.Certificate:
    try:
        return x5c_to_cert(signature["header"]["x5c"][0])
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise BadSignature(f"malformed signing certificate: {exc}") from exc


def _verify_jws(card: dict[str, Any], signature: dict[str, Any], cert: x509.Certificate) -> bytes:
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
    return message


def _pinned_identity(cert: x509.Certificate) -> str:
    try:
        return identity_from_cert(cert)
    except (x509.ExtensionNotFound, ValueError) as exc:
        raise IdentityMismatch(f"signing certificate has no URI SAN identity: {exc}") from exc


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
    require_bundle: bool = True,
    max_age: timedelta | None = None,
    trust_root: TrustRoot | None = None,
    expected_oidc_issuer: str | None = None,
    staging: bool = False,
) -> VerifyResult:
    """Verify a signed Agent Card, failing closed with a distinct error per control.

    A card carrying a ``sigstoreBundle`` header (a keyless Sigstore signature) is
    verified through Sigstore's offline bundle verifier: the Rekor inclusion proof
    travels in the bundle, so transparency-log inclusion is confirmed without a
    log-index REST lookup. A card without a bundle is a local self-signed card,
    accepted only when ``require_bundle`` is off.

    Args:
        card_json: The served, signed card as a dict.
        expected_identity: The certificate URI SAN identity to pin.
        require_bundle: If true (the default), a Sigstore bundle is mandatory; a
            card without one is rejected so transparency-log inclusion is never
            silently skipped. Turn it off only for local, self-signed cards.
        max_age: If set, reject signatures whose cert is older than this.
        trust_root: If set, cryptographically anchor the local path by chaining
            the leaf to a trusted Fulcio root; a self-signed cert is then rejected.
            Ignored on the bundle path, which carries its own Sigstore trust root.
        expected_oidc_issuer: Required on the keyless bundle path and whenever
            ``trust_root`` is set; the Fulcio OIDC issuer must equal this value.
            Issuer pinning is the central control on both trusted paths: without
            it any OIDC provider Fulcio trusts could mint a cert for the same
            identity and be accepted.
        staging: Verify bundle cards against the Sigstore staging trust root.

    Returns:
        A ``VerifyResult`` on success.

    Raises:
        ValueError: If the card carries a Sigstore bundle, or ``trust_root`` is
            set, without ``expected_oidc_issuer``.
        MissingSignature, BadSignature, IdentityMismatch, CardExpired,
        UntrustedCertificate, MissingRekorEntry, BundleVerificationError: On the
        corresponding failure.
    """
    signatures = card_json.get("signatures")
    if not signatures:
        raise MissingSignature("card has no signatures")
    if not isinstance(signatures, list) or not isinstance(signatures[0], dict):
        raise BadSignature("card signatures must be an array of objects")
    signature = signatures[0]

    cert = _load_cert(signature)
    message = _verify_jws(card_json, signature, cert)

    identity = _pinned_identity(cert)
    if identity != expected_identity:
        raise IdentityMismatch(f"expected identity {expected_identity!r}, got {identity!r}")

    _check_freshness(cert, max_age)

    if "sigstoreBundle" in signature["header"]:
        if expected_oidc_issuer is None:
            raise ValueError(
                "expected_oidc_issuer is required on the keyless bundle path: issuer "
                "pinning is the central control of the trusted path"
            )
        return _verify_bundle_card(
            signature,
            cert,
            message,
            identity=identity,
            expected_oidc_issuer=expected_oidc_issuer,
            staging=staging,
        )

    return _verify_local_card(
        signature,
        cert,
        identity=identity,
        require_bundle=require_bundle,
        trust_root=trust_root,
        expected_oidc_issuer=expected_oidc_issuer,
    )


def _verify_local_card(
    signature: dict[str, Any],
    cert: x509.Certificate,
    *,
    identity: str,
    require_bundle: bool,
    trust_root: TrustRoot | None,
    expected_oidc_issuer: str | None,
) -> VerifyResult:
    if require_bundle:
        raise MissingRekorEntry(
            "card carries no Sigstore bundle; transparency-log inclusion is required"
        )

    if trust_root is not None:
        if expected_oidc_issuer is None:
            raise ValueError(
                "expected_oidc_issuer is required when trust_root is set: issuer "
                "pinning is the central control of the anchored path"
            )
        _enforce_trust(signature, cert, trust_root, expected_oidc_issuer)

    return VerifyResult(identity=identity, rekor_log_index=None)


def _verify_bundle_card(
    signature: dict[str, Any],
    cert: x509.Certificate,
    message: bytes,
    *,
    identity: str,
    expected_oidc_issuer: str,
    staging: bool,
) -> VerifyResult:
    from ellingson_card.keyless_verify import verify_bundle

    bundle_json = signature["header"]["sigstoreBundle"]
    if not isinstance(bundle_json, str):
        raise BundleVerificationError("sigstoreBundle header must be a string")
    rekor_log_index = verify_bundle(
        message,
        bundle_json,
        expected_identity=identity,
        expected_leaf_der=cert.public_bytes(_DER),
        staging=staging,
        expected_issuer=expected_oidc_issuer,
    )
    return VerifyResult(identity=identity, rekor_log_index=rekor_log_index)
