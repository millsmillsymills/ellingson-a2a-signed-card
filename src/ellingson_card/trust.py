"""Cryptographic trust anchoring for Fulcio-issued signing certificates.

The hermetic local path mints a self-signed certificate, so by default the
verifier only string-matches the URI SAN. A production verifier must instead
anchor trust: build the path from the leaf to a trusted Fulcio root, enforce
certificate validity and CA constraints at each hop, and confirm the Fulcio
OIDC-issuer extension. Configuring a ``TrustRoot`` switches the verifier from
the self-signed-friendly path to this anchored path.

Chain building consumes intermediates from both the ``x5c`` header and the
trust root's own anchors, matching how Sigstore distributes leaf-only bundles
and reconstructs the chain from the trust bundle at verify time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from ellingson_card.errors import UntrustedCertificate

# Fulcio v1 OIDC-issuer extension (the plain-string form).
FULCIO_OIDC_ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")

_MAX_CHAIN_DEPTH = 8


@dataclass(frozen=True)
class TrustRoot:
    """Trusted CA anchors: the Fulcio root, plus any intermediates to include."""

    anchors: tuple[x509.Certificate, ...]

    @classmethod
    def from_pem(cls, pem_data: bytes) -> TrustRoot:
        """Load a trust root from a PEM bundle of one or more CA certificates."""
        return cls(tuple(x509.load_pem_x509_certificates(pem_data)))


def verify_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    trust_root: TrustRoot,
    *,
    at_time: datetime,
) -> None:
    """Verify that ``leaf`` chains to a trusted anchor in ``trust_root``.

    Walks from the leaf upward, at each hop checking the certificate's validity
    window contains ``at_time`` and that the issuer cryptographically signed it.
    Non-anchor issuers must assert ``BasicConstraints(ca=True)``. Terminates
    successfully when the current certificate is itself a trusted anchor.

    Raises:
        UntrustedCertificate: If no path to a trusted anchor exists, a hop is
            expired, an issuer is not a CA, or the chain exceeds the depth limit.
    """
    anchor_fingerprints = {_fingerprint(c) for c in trust_root.anchors}
    pool = [*intermediates, *trust_root.anchors]
    cert = leaf
    for _ in range(_MAX_CHAIN_DEPTH):
        _check_validity(cert, at_time)
        if _fingerprint(cert) in anchor_fingerprints:
            return
        issuer = _find_issuer(cert, pool)
        if issuer is None:
            raise UntrustedCertificate(f"no trusted issuer for {cert.subject.rfc4514_string()!r}")
        if _fingerprint(issuer) not in anchor_fingerprints:
            _require_ca(issuer)
        cert = issuer
    raise UntrustedCertificate("certificate chain exceeds maximum depth")


def oidc_issuer(cert: x509.Certificate) -> str | None:
    """Return the Fulcio OIDC-issuer extension value, or ``None`` if absent."""
    try:
        ext = cert.extensions.get_extension_for_oid(FULCIO_OIDC_ISSUER_OID)
    except x509.ExtensionNotFound:
        return None
    value = ext.value
    if not isinstance(value, x509.UnrecognizedExtension):
        return None
    try:
        return value.value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _fingerprint(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(encoding=Encoding.DER)


def _check_validity(cert: x509.Certificate, at_time: datetime) -> None:
    if at_time < cert.not_valid_before_utc or at_time > cert.not_valid_after_utc:
        raise UntrustedCertificate(
            f"certificate {cert.subject.rfc4514_string()!r} is not valid at {at_time.isoformat()}"
        )


def _find_issuer(cert: x509.Certificate, pool: list[x509.Certificate]) -> x509.Certificate | None:
    for candidate in pool:
        if candidate.subject == cert.issuer and _signed_by(cert, candidate):
            return candidate
    return None


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    public_key = issuer.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return False
    algorithm = cert.signature_hash_algorithm
    if algorithm is None:
        return False
    try:
        public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(algorithm))
    except InvalidSignature:
        return False
    return True


def _require_ca(cert: x509.Certificate) -> None:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise UntrustedCertificate(
            f"issuer {cert.subject.rfc4514_string()!r} has no basic constraints"
        ) from exc
    if not constraints.ca:
        raise UntrustedCertificate(f"issuer {cert.subject.rfc4514_string()!r} is not a CA")
