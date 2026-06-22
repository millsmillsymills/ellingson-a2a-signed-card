"""Emit a v1.0-spec-native ``AgentCardSignature`` (RFC 7515 JWS, ES256).

The signature uses a detached payload: the JWS payload is the RFC 8785 JCS
canonical form of the card (signatures excluded), never embedded in the card.
The Sigstore/Fulcio certificate chain travels in the unprotected ``x5c`` header;
Rekor transparency-log linkage travels in a custom ``rekorLogIndex`` header field
(the spec's JWS shape has no native slot for it).
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


def signing_input(card: dict[str, Any], protected_b64: str) -> bytes:
    """Return the JWS signing input for a card with the given protected header."""
    return f"{protected_b64}.{_b64url(canonicalize(card))}".encode("ascii")


def _der_to_raw(der_signature: bytes) -> bytes:
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(_COORD_BYTES, "big") + s.to_bytes(_COORD_BYTES, "big")


def sign_card(
    card: dict[str, Any],
    key: ec.EllipticCurvePrivateKey,
    cert: x509.Certificate,
    rekor_log_index: int | None = None,
) -> dict[str, Any]:
    """Sign a card and return a spec-native ``AgentCardSignature`` dict.

    Args:
        card: The Agent Card to sign (served JSON; ``signatures`` is excluded).
        key: The ES256 private key.
        cert: The signing certificate (self-signed locally, Fulcio in CI).
        rekor_log_index: Optional Rekor transparency-log index to bind.

    Returns:
        ``{"protected", "signature", "header"}`` per A2A v1.0 §4.4.7.
    """
    protected_b64 = _b64url(json.dumps({"alg": "ES256"}, separators=(",", ":")).encode())
    der = key.sign(signing_input(card, protected_b64), ec.ECDSA(hashes.SHA256()))
    header: dict[str, Any] = {"x5c": cert_to_x5c(cert)}
    if rekor_log_index is not None:
        header["rekorLogIndex"] = rekor_log_index
    return {
        "protected": protected_b64,
        "signature": _b64url(_der_to_raw(der)),
        "header": header,
    }


def attach_signature(card: dict[str, Any], signature: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the card with ``signatures`` set to ``[signature]``."""
    return {**card, "signatures": [signature]}
