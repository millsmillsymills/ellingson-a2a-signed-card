"""Sigstore keyless signing adapter.

This is the only path that depends on Sigstore and ambient CI OIDC, so it is
exercised by the signing workflow rather than unit tests; the crypto assembly it
feeds (``assemble_keyless_signature``) is unit-tested. Sigstore is imported
lazily so the local sign/verify/serve paths never load it.

The artifact handed to Sigstore is exactly the JWS signing input, so the ES256
signature Sigstore returns is a valid detached JWS signature over the card's JCS
canonical form — no second signing operation is needed.
"""

from __future__ import annotations

from typing import Any

from ellingson_card.errors import SigningError
from ellingson_card.signer import assemble_keyless_signature, protected_b64, signing_input


def sign_card_keyless(card: dict[str, Any], *, staging: bool = False) -> dict[str, Any]:
    """Sign a card with Sigstore keyless signing and return an ``AgentCardSignature``.

    Args:
        card: The Agent Card to sign.
        staging: Use the Sigstore staging instance instead of production.

    Returns:
        A spec-native ``AgentCardSignature`` carrying the Fulcio ``x5c`` chain and
        the full Sigstore bundle (with the Rekor inclusion proof) for offline
        transparency-log verification.

    Raises:
        SigningError: If no ambient OIDC credential is available, the token is
            invalid, or Sigstore signing fails.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import ClientTrustConfig, SigningContext

    try:
        raw_token = detect_credential()
    except Exception as exc:  # noqa: BLE001 -- ambient-credential probe boundary, fail closed
        raise SigningError(f"ambient OIDC credential detection failed: {exc}") from exc
    if raw_token is None:
        raise SigningError("no ambient OIDC credential; run in a CI job with id-token: write")

    try:
        token = IdentityToken(raw_token)
    except Exception as exc:  # noqa: BLE001 -- untrusted-token parse boundary, fail closed
        raise SigningError(f"invalid ambient OIDC token: {exc}") from exc

    protected = protected_b64()
    message = signing_input(card, protected)
    # Trust-config fetch and signing talk to Fulcio/Rekor; network and service
    # errors surface as assorted Sigstore/requests types. Wrap the whole boundary
    # so any failure lands as a one-line SigningError instead of a traceback.
    try:
        trust = ClientTrustConfig.staging() if staging else ClientTrustConfig.production()
        context = SigningContext.from_trust_config(trust)
        with context.signer(token) as signer:
            bundle = signer.sign_artifact(message)
        leaf_der = bundle.signing_certificate.public_bytes(Encoding.DER)
        return assemble_keyless_signature(protected, bundle.signature, leaf_der, bundle.to_json())
    except Exception as exc:  # noqa: BLE001 -- Sigstore signing boundary, fail closed
        raise SigningError(f"Sigstore keyless signing failed: {exc}") from exc
