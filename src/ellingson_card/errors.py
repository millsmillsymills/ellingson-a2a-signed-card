"""Distinct, testable verification errors. The verifier fails closed: every
rejection raises a specific subclass so callers (and the CLI exit code) can tell
exactly which control rejected the card.
"""

from __future__ import annotations


class VerificationError(Exception):
    """Base class for all Agent Card verification failures."""


class MissingSignature(VerificationError):
    """The card carries no ``signatures`` entry."""


class BadSignature(VerificationError):
    """The JWS signature does not verify against the card's canonical bytes."""


class IdentityMismatch(VerificationError):
    """The signing certificate identity does not match the pinned identity."""


class UntrustedCertificate(VerificationError):
    """The signing certificate does not chain to a trusted root, or its Fulcio
    OIDC-issuer extension does not match the expected issuer."""


class MissingRekorEntry(VerificationError):
    """No Rekor transparency-log entry is present or it could not be confirmed."""


class BundleVerificationError(VerificationError):
    """The keyless signature's Sigstore bundle failed offline verification: a
    malformed bundle, a certificate that does not chain to Fulcio, an identity
    mismatch, or a Rekor inclusion proof that does not bind to this card."""


class CardExpired(VerificationError):
    """The signing certificate is expired or older than the allowed max age."""
