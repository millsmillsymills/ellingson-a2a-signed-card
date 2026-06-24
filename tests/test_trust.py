from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hypothesis import given
from hypothesis import strategies as st

from ellingson_card.errors import UntrustedCertificate
from ellingson_card.keys import cert_to_x5c, x5c_to_cert
from ellingson_card.trust import (
    FULCIO_OIDC_ISSUER_OID,
    FULCIO_OIDC_ISSUER_V2_OID,
    TrustRoot,
    oidc_issuer,
    verify_chain,
)
from ellingson_card.trust import (
    _der_utf8string as decode_der_utf8string,
)
from tests.conftest import key_usage as build_key_usage

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/tags/v1"
ISSUER = "https://token.actions.githubusercontent.com"
NOW = datetime(2026, 6, 22, tzinfo=UTC)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn, *, issuer_cert=None, issuer_key=None, path_length=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn)
    issuer_name = issuer_cert.subject if issuer_cert else subject
    signing_key = issuer_key or key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .sign(signing_key, hashes.SHA256())
    )
    return key, cert


def _der_utf8string(value):
    encoded = value.encode("utf-8")
    return b"\x0c" + bytes([len(encoded)]) + encoded


def _leaf(
    issuer_cert,
    issuer_key,
    *,
    identity=IDENTITY,
    issuer_oidc=ISSUER,
    code_signing=True,
    key_usage=True,
    key_usage_critical=True,
    digital_signature=True,
    issuer_oidc_v2=None,
    issuer_oidc_v2_raw=None,
    not_after=None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=False
        )
    )
    if code_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False
        )
    if key_usage:
        builder = builder.add_extension(
            build_key_usage(digital_signature), critical=key_usage_critical
        )
    if issuer_oidc is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(FULCIO_OIDC_ISSUER_OID, issuer_oidc.encode()), critical=False
        )
    raw_v2 = issuer_oidc_v2_raw
    if raw_v2 is None and issuer_oidc_v2 is not None:
        raw_v2 = _der_utf8string(issuer_oidc_v2)
    if raw_v2 is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(FULCIO_OIDC_ISSUER_V2_OID, raw_v2),
            critical=False,
        )
    return key, builder.sign(issuer_key, hashes.SHA256())


def test_verify_chain_accepts_leaf_under_trusted_root():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key)
    verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_accepts_leaf_through_intermediate():
    root_key, root = _ca("root")
    int_key, intermediate = _ca("intermediate", issuer_cert=root, issuer_key=root_key)
    _, leaf = _leaf(intermediate, int_key)
    verify_chain(leaf, [intermediate], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_uses_intermediates_from_trust_root():
    root_key, root = _ca("root")
    int_key, intermediate = _ca("intermediate", issuer_cert=root, issuer_key=root_key)
    _, leaf = _leaf(intermediate, int_key)
    verify_chain(leaf, [], TrustRoot((intermediate, root)), at_time=NOW)


def test_verify_chain_rejects_self_signed_leaf():
    key = ec.generate_private_key(ec.SECP256R1())
    self_signed = (
        x509.CertificateBuilder()
        .subject_name(_name("leaf"))
        .issuer_name(_name("leaf"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(IDENTITY)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    root_key, root = _ca("root")
    with pytest.raises(UntrustedCertificate):
        verify_chain(self_signed, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_non_ec_issuer():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _name("rsa-root")
    rsa_root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rsa_key, hashes.SHA256())
    )
    _, leaf = _leaf(rsa_root, rsa_key)
    with pytest.raises(UntrustedCertificate, match="no trusted issuer"):
        verify_chain(leaf, [], TrustRoot((rsa_root,)), at_time=NOW)


def test_verify_chain_rejects_untrusted_root():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key)
    other_key, other_root = _ca("other-root")
    with pytest.raises(UntrustedCertificate):
        verify_chain(leaf, [], TrustRoot((other_root,)), at_time=NOW)


def test_verify_chain_rejects_expired_leaf():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, not_after=NOW - timedelta(hours=1))
    with pytest.raises(UntrustedCertificate):
        verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_non_ca_intermediate():
    root_key, root = _ca("root")
    forged_key, forged = _leaf(root, root_key, identity="https://ca-impersonator")
    _, leaf = _leaf(forged, forged_key)
    with pytest.raises(UntrustedCertificate):
        verify_chain(leaf, [forged], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_leaf_without_code_signing_eku():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, code_signing=False)
    with pytest.raises(UntrustedCertificate):
        verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_leaf_without_key_usage():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, key_usage=False)
    with pytest.raises(UntrustedCertificate, match="key usage"):
        verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_leaf_without_digital_signature_usage():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, digital_signature=False)
    with pytest.raises(UntrustedCertificate, match="digital signature"):
        verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_non_critical_key_usage():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, key_usage_critical=False)
    with pytest.raises(UntrustedCertificate, match="key usage"):
        verify_chain(leaf, [], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_rejects_pathlen_zero_intermediate_signing_intermediate():
    root_key, root = _ca("root")
    zero_key, zero = _ca("pathlen-zero", issuer_cert=root, issuer_key=root_key, path_length=0)
    sub_key, sub = _ca("sub-intermediate", issuer_cert=zero, issuer_key=zero_key)
    _, leaf = _leaf(sub, sub_key)
    with pytest.raises(UntrustedCertificate):
        verify_chain(leaf, [sub, zero], TrustRoot((root,)), at_time=NOW)


def test_verify_chain_accepts_pathlen_one_intermediate():
    root_key, root = _ca("root")
    one_key, one = _ca("pathlen-one", issuer_cert=root, issuer_key=root_key, path_length=1)
    sub_key, sub = _ca("sub-intermediate", issuer_cert=one, issuer_key=one_key, path_length=0)
    _, leaf = _leaf(sub, sub_key)
    verify_chain(leaf, [sub, one], TrustRoot((root,)), at_time=NOW)


def test_oidc_issuer_reads_fulcio_extension():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key)
    assert oidc_issuer(leaf) == ISSUER


def test_oidc_issuer_none_when_absent():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, issuer_oidc=None)
    assert oidc_issuer(leaf) is None


def test_oidc_issuer_reads_v2_der_utf8string():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, issuer_oidc=None, issuer_oidc_v2=ISSUER)
    assert oidc_issuer(leaf) == ISSUER


def test_oidc_issuer_prefers_v2_over_v1():
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, issuer_oidc="https://legacy.example", issuer_oidc_v2=ISSUER)
    assert oidc_issuer(leaf) == ISSUER


def test_der_utf8string_decodes_minimal_value():
    assert decode_der_utf8string(b"\x0c\x02hi") == "hi"


@pytest.mark.parametrize(
    "raw",
    [
        b"\x0c\x00",  # empty value
        b"\x0c\x81\x02hi",  # non-minimal long form (fits short form)
        b"\x0c\x82\x00\x02hi",  # leading-zero length octet
    ],
)
def test_der_utf8string_rejects_non_minimal_der(raw):
    assert decode_der_utf8string(raw) is None


@pytest.mark.parametrize(
    "raw_v2",
    [
        b"\x0d\x05hello",  # wrong tag (not UTF8String)
        b"\x0c\x82\x00",  # long-form length octets truncated
        b"\x0c\x05hi",  # declared length exceeds payload
        b"\x0c\x02hi!",  # trailing bytes after declared length
        b"\x0c\x01\xff",  # invalid UTF-8 payload
    ],
    ids=[
        "wrong-tag",
        "truncated-long-form-length",
        "length-exceeds-payload",
        "trailing-bytes",
        "invalid-utf8",
    ],
)
def test_oidc_issuer_malformed_v2_fails_closed(raw_v2):
    root_key, root = _ca("root")
    _, leaf = _leaf(root, root_key, issuer_oidc=ISSUER, issuer_oidc_v2_raw=raw_v2)
    assert oidc_issuer(leaf) is None


def test_der_utf8string_decodes_long_form_length():
    value = "x" * 200
    encoded = value.encode("utf-8")
    der = b"\x0c\x81" + bytes([len(encoded)]) + encoded
    assert decode_der_utf8string(der) == value


def test_der_utf8string_accepts_long_form_length_boundary():
    value = "a" * 128
    der = b"\x0c\x81\x80" + value.encode("utf-8")
    assert decode_der_utf8string(der) == value


def test_der_utf8string_rejects_indefinite_length():
    assert decode_der_utf8string(b"\x0c\x80") is None


def test_der_utf8string_rejects_invalid_utf8():
    assert decode_der_utf8string(b"\x0c\x01\xff") is None


def _minimal_der_utf8string(text):
    encoded = text.encode("utf-8")
    length = len(encoded)
    if length < 0x80:
        length_octets = bytes([length])
    else:
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        length_octets = bytes([0x80 | len(body)]) + body
    return b"\x0c" + length_octets + encoded


@given(st.binary())
def test_der_utf8string_never_raises_on_arbitrary_bytes(data):
    result = decode_der_utf8string(data)
    assert result is None or isinstance(result, str)


@given(st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cs"])))
def test_der_utf8string_round_trips_valid_encodings(text):
    der = _minimal_der_utf8string(text)
    assert decode_der_utf8string(der) == text


def test_cert_to_x5c_carries_chain():
    root_key, root = _ca("root")
    int_key, intermediate = _ca("intermediate", issuer_cert=root, issuer_key=root_key)
    _, leaf = _leaf(intermediate, int_key)
    x5c = cert_to_x5c(leaf, intermediate, root)
    assert len(x5c) == 3
    assert x5c_to_cert(x5c[0]).subject == leaf.subject
    assert x5c_to_cert(x5c[2]).subject == root.subject
