"""Ephemeral ES256 signing material for the hermetic local sign/verify path.

In CI the signing certificate comes from Sigstore/Fulcio (keyless). For local
demos and tests we mint an ephemeral P-256 key and a self-signed certificate
that carries the signer identity as a URI SAN, mirroring how Fulcio encodes the
OIDC identity. No long-lived key is ever written to disk.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_signing_material(
    identity: str,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Generate a P-256 key and a self-signed cert with ``identity`` as a URI SAN.

    Args:
        identity: The signer identity to pin (e.g. a workflow ref or email URI).

    Returns:
        A tuple of (private key, self-signed certificate).
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ellingson Signed Card")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def cert_to_x5c(cert: x509.Certificate, *intermediates: x509.Certificate) -> list[str]:
    """Return the base64-encoded DER ``x5c`` chain, leaf first.

    Args:
        cert: The leaf signing certificate.
        intermediates: Any chain certificates to append after the leaf, in
            order toward the root.
    """
    chain = (cert, *intermediates)
    return [
        base64.b64encode(c.public_bytes(encoding=serialization.Encoding.DER)).decode("ascii")
        for c in chain
    ]


def x5c_to_cert(x5c_entry: str) -> x509.Certificate:
    """Parse a single base64 DER ``x5c`` entry back into a certificate."""
    return x509.load_der_x509_certificate(base64.b64decode(x5c_entry))


def identity_from_cert(cert: x509.Certificate) -> str:
    """Extract the first URI SAN from a certificate.

    Raises:
        ValueError: If the certificate has no URI SAN.
    """
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    if not uris:
        raise ValueError("certificate has no URI SAN identity")
    return uris[0]
