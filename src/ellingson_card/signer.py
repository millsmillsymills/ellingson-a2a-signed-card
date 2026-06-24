"""Emit a v1.0-spec-native ``AgentCardSignature`` (RFC 7515 JWS, ES256).

The signature uses a detached payload: the JWS payload is the RFC 8785 JCS
canonical form of the card (signatures excluded), never embedded in the card.
The Sigstore/Fulcio certificate chain travels in the unprotected ``x5c`` header;
for keyless signatures the full Sigstore bundle (with the Rekor inclusion proof)
travels in a custom ``sigstoreBundle`` header field, since the spec's JWS shape
has no native slot for transparency-log material.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ellingson_card.canonical import canonicalize
from ellingson_card.keys import cert_to_x5c

if TYPE_CHECKING:
    from cryptography import x509

_COORD_BYTES = 32  # P-256 field element width; ES256 signature is R||S = 64 bytes


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def protected_b64() -> str:
    """Return the base64url-encoded ES256 JWS protected header."""
    return _b64url(json.dumps({"alg": "ES256"}, separators=(",", ":")).encode())


def signing_input(card: dict[str, Any], protected: str) -> bytes:
    """Return the JWS signing input for a card with the given protected header."""
    return f"{protected}.{_b64url(canonicalize(card))}".encode("ascii")


def _der_to_raw(der_signature: bytes) -> bytes:
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(_COORD_BYTES, "big") + s.to_bytes(_COORD_BYTES, "big")


def sign_card(
    card: dict[str, Any],
    key: ec.EllipticCurvePrivateKey,
    cert: x509.Certificate,
) -> dict[str, Any]:
    """Sign a card and return a spec-native ``AgentCardSignature`` dict.

    Args:
        card: The Agent Card to sign (served JSON; ``signatures`` is excluded).
        key: The ES256 private key.
        cert: The signing certificate (self-signed locally, Fulcio in CI).

    Returns:
        ``{"protected", "signature", "header"}`` per A2A v1.0 §4.4.7.
    """
    protected = protected_b64()
    der = key.sign(signing_input(card, protected), ec.ECDSA(hashes.SHA256()))
    return {
        "protected": protected,
        "signature": _b64url(_der_to_raw(der)),
        "header": {"x5c": cert_to_x5c(cert)},
    }


def assemble_keyless_signature(
    protected: str,
    der_signature: bytes,
    leaf_cert_der: bytes,
    sigstore_bundle: str,
) -> dict[str, Any]:
    """Assemble an ``AgentCardSignature`` from Sigstore keyless outputs.

    The Fulcio leaf certificate goes in ``x5c`` to keep the card a valid A2A JWS;
    the full Sigstore bundle (cert chain plus the Rekor inclusion proof and signed
    checkpoint) goes in the custom ``sigstoreBundle`` header field so the verifier
    can confirm transparency-log inclusion offline. The signature is the same
    ES256 DER value Sigstore produced over the JWS signing input, re-encoded as
    JOSE R||S.

    Args:
        protected: The base64url ES256 protected header (see ``protected_b64``).
        der_signature: The DER-encoded ECDSA signature from Sigstore.
        leaf_cert_der: The Fulcio leaf certificate in DER form.
        sigstore_bundle: The serialized Sigstore bundle JSON (``Bundle.to_json``).

    Returns:
        A spec-native ``AgentCardSignature`` dict.
    """
    x5c = [base64.b64encode(leaf_cert_der).decode("ascii")]
    return {
        "protected": protected,
        "signature": _b64url(_der_to_raw(der_signature)),
        "header": {"x5c": x5c, "sigstoreBundle": sigstore_bundle},
    }


def attach_signature(card: dict[str, Any], signature: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the card with ``signatures`` set to ``[signature]``."""
    return {**card, "signatures": [signature]}
