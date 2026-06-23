"""Offline verification of a keyless signature's Sigstore bundle.

Keyless-signed cards carry the full Sigstore bundle (Fulcio chain plus the Rekor
inclusion proof and signed checkpoint) in the ``sigstoreBundle`` header. This
module hands that bundle to Sigstore's own verifier, which confirms the
certificate chains to Fulcio, the SAN identity (and optionally OIDC issuer)
match, and the artifact is included in the Rekor transparency log -- all from the
bundle's inclusion proof and checkpoint, with no Rekor network lookup.

Verifying the proof offline is what makes this robust to Rekor's v1->v2
migration: Sigstore signs against whichever log its trust config selects (v2 on
staging) and the inclusion proof travels in the bundle, so verification never
depends on a log-index REST lookup against a specific Rekor version.

Sigstore is imported lazily so the local self-signed verify path never loads it.
"""

from __future__ import annotations

from ellingson_card.errors import BundleVerificationError

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"


def verify_bundle(
    message: bytes,
    bundle_json: str,
    *,
    expected_identity: str,
    expected_leaf_der: bytes,
    staging: bool = False,
    expected_issuer: str | None = None,
) -> int:
    """Verify a card's Sigstore bundle offline and return its Rekor log index.

    Args:
        message: The JWS signing input the bundle must attest (``signing_input``).
        bundle_json: The serialized Sigstore bundle from the ``sigstoreBundle``
            header.
        expected_identity: The URI SAN identity to pin (the workflow identity).
        expected_leaf_der: The DER leaf certificate from the card's ``x5c``; the
            bundle's signing certificate must equal it, binding the spec-native
            signature to the bundle being trusted.
        staging: Verify against the Sigstore staging trust root instead of
            production.
        expected_issuer: If set, also pin the Fulcio OIDC issuer.

    Returns:
        The Rekor transparency-log index recorded in the bundle.

    Raises:
        BundleVerificationError: If the bundle is malformed, its certificate does
            not match the card's ``x5c`` leaf, or Sigstore rejects it (bad chain,
            identity mismatch, or inclusion proof that does not bind to
            ``message``).
    """
    from cryptography.hazmat.primitives.serialization import Encoding
    from sigstore.errors import VerificationError
    from sigstore.models import Bundle
    from sigstore.verify import Verifier, policy

    try:
        bundle = Bundle.from_json(bundle_json)
    except (ValueError, KeyError, TypeError) as exc:
        raise BundleVerificationError(f"malformed Sigstore bundle: {exc}") from exc

    if bundle.signing_certificate.public_bytes(Encoding.DER) != expected_leaf_der:
        raise BundleVerificationError("bundle certificate does not match the card's x5c leaf")

    verifier = Verifier.staging(offline=True) if staging else Verifier.production(offline=True)
    pinned = policy.Identity(identity=expected_identity, issuer=expected_issuer)
    try:
        verifier.verify_artifact(message, bundle, pinned)
    except VerificationError as exc:
        raise BundleVerificationError(str(exc)) from exc

    return int(bundle.log_entry._inner.log_index)  # noqa: SLF001 (index only exposed here)
