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
from cryptography.x509.oid import ExtendedKeyUsageOID

from ellingson_card.errors import UntrustedCertificate

# Fulcio v1 OIDC-issuer extension (the plain-string form).
FULCIO_OIDC_ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
# Fulcio v2 OIDC-issuer extension (DER-encoded UTF8String); current default.
FULCIO_OIDC_ISSUER_V2_OID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.8")

_DER_UTF8STRING_TAG = 0x0C

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
    The leaf must carry the code-signing extended key usage and a
    ``KeyUsage`` permitting digital signatures. Non-anchor issuers must assert
    ``BasicConstraints(ca=True)`` and honor their ``pathLenConstraint`` against
    the number of intermediate CAs already below them. Terminates successfully
    when the current certificate is itself a trusted anchor.

    Raises:
        UntrustedCertificate: If no path to a trusted anchor exists, a hop is
            expired, the leaf lacks code-signing EKU or digital-signature key
            usage, an issuer is not a CA, a ``pathLenConstraint`` is exceeded,
            or the chain exceeds the depth limit.
    """
    anchor_fingerprints = {_fingerprint(c) for c in trust_root.anchors}
    pool = [*intermediates, *trust_root.anchors]
    _require_code_signing_eku(leaf)
    _require_digital_signature(leaf)
    cert = leaf
    intermediate_ca_count = 0
    for _ in range(_MAX_CHAIN_DEPTH):
        _check_validity(cert, at_time)
        if _fingerprint(cert) in anchor_fingerprints:
            return
        issuer = _find_issuer(cert, pool)
        if issuer is None:
            raise UntrustedCertificate(f"no trusted issuer for {cert.subject.rfc4514_string()!r}")
        if _fingerprint(issuer) not in anchor_fingerprints:
            _require_ca(issuer, intermediate_ca_count)
            intermediate_ca_count += 1
        cert = issuer
    raise UntrustedCertificate("certificate chain exceeds maximum depth")


def oidc_issuer(cert: x509.Certificate) -> str | None:
    """Return the Fulcio OIDC-issuer extension value, or ``None`` if absent.

    Modern Fulcio certs carry the issuer in the DER-encoded UTF8String extension
    ``.1.8``; older ones used the plain-string ``.1.1``. Prefers ``.1.8`` when
    present (a malformed ``.1.8`` yields ``None`` so the verifier fails closed
    rather than reading the legacy field), and falls back to ``.1.1`` otherwise.
    """
    raw_v2 = _raw_extension(cert, FULCIO_OIDC_ISSUER_V2_OID)
    if raw_v2 is not None:
        return _der_utf8string(raw_v2)
    raw_v1 = _raw_extension(cert, FULCIO_OIDC_ISSUER_OID)
    if raw_v1 is None:
        return None
    try:
        return raw_v1.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _raw_extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound:
        return None
    value = ext.value
    if not isinstance(value, x509.UnrecognizedExtension):
        return None
    return value.value


def _der_utf8string(data: bytes) -> str | None:
    """Decode a single DER-encoded UTF8String, or ``None`` if malformed.

    Enforces strict DER: the length must use the minimal encoding (short form
    below 128, no redundant or non-minimal long form) and the value must be
    non-empty. An empty or meaninglessly-encoded issuer is treated as malformed
    so the verifier fails closed, keeping the "malformed → None" contract uniform.
    """
    if len(data) < 2 or data[0] != _DER_UTF8STRING_TAG:
        return None
    length_octet = data[1]
    if length_octet < 0x80:
        start, length = 2, length_octet
    else:
        num_octets = length_octet & 0x7F
        if num_octets == 0 or len(data) < 2 + num_octets:
            return None
        start = 2 + num_octets
        length_bytes = data[2:start]
        length = int.from_bytes(length_bytes, "big")
        if length_bytes[0] == 0 or length < 0x80:
            return None
    if length == 0 or len(data) != start + length:
        return None
    try:
        return data[start : start + length].decode("utf-8")
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


def _require_code_signing_eku(cert: x509.Certificate) -> None:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise UntrustedCertificate(
            f"leaf {cert.subject.rfc4514_string()!r} has no extended key usage"
        ) from exc
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise UntrustedCertificate(
            f"leaf {cert.subject.rfc4514_string()!r} is not a code-signing certificate"
        )


def _require_digital_signature(cert: x509.Certificate) -> None:
    try:
        extension = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        raise UntrustedCertificate(
            f"leaf {cert.subject.rfc4514_string()!r} has no key usage"
        ) from exc
    if not extension.critical:
        raise UntrustedCertificate(
            f"leaf {cert.subject.rfc4514_string()!r} key usage is not marked critical"
        )
    key_usage = extension.value
    if not key_usage.digital_signature:
        raise UntrustedCertificate(
            f"leaf {cert.subject.rfc4514_string()!r} key usage does not permit digital signatures"
        )


def _require_ca(cert: x509.Certificate, intermediates_below: int) -> None:
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise UntrustedCertificate(
            f"issuer {cert.subject.rfc4514_string()!r} has no basic constraints"
        ) from exc
    if not constraints.ca:
        raise UntrustedCertificate(f"issuer {cert.subject.rfc4514_string()!r} is not a CA")
    if constraints.path_length is not None and intermediates_below > constraints.path_length:
        raise UntrustedCertificate(
            f"issuer {cert.subject.rfc4514_string()!r} pathLenConstraint "
            f"{constraints.path_length} exceeded"
        )
