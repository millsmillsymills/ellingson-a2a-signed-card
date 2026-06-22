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

from ellingson_card.signer import assemble_keyless_signature, protected_b64, signing_input


def _rekor_log_index(log_entry: Any) -> int:
    return int(log_entry._inner.log_index)  # noqa: SLF001 (sigstore exposes index only here)


def sign_card_keyless(card: dict[str, Any], *, staging: bool = False) -> dict[str, Any]:
    """Sign a card with Sigstore keyless signing and return an ``AgentCardSignature``.

    Args:
        card: The Agent Card to sign.
        staging: Use the Sigstore staging instance instead of production.

    Returns:
        A spec-native ``AgentCardSignature`` carrying the Fulcio ``x5c`` chain and
        the Rekor ``rekorLogIndex``.

    Raises:
        RuntimeError: If no ambient OIDC credential is available.
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import ClientTrustConfig, SigningContext

    raw_token = detect_credential()
    if raw_token is None:
        raise RuntimeError("no ambient OIDC credential; run in a CI job with id-token: write")

    token = IdentityToken(raw_token)
    trust = ClientTrustConfig.staging() if staging else ClientTrustConfig.production()
    context = SigningContext.from_trust_config(trust)

    protected = protected_b64()
    message = signing_input(card, protected)
    with context.signer(token) as signer:
        bundle = signer.sign_artifact(message)

    leaf_der = bundle.signing_certificate.public_bytes(Encoding.DER)
    return assemble_keyless_signature(
        protected,
        bundle.signature,
        leaf_der,
        _rekor_log_index(bundle.log_entry),
    )
