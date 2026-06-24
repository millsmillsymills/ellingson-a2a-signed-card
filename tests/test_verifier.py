from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ellingson_card.errors import (
    BadSignature,
    BundleVerificationError,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
    UntrustedCertificate,
)
from ellingson_card.keys import cert_to_x5c, generate_signing_material
from ellingson_card.signer import attach_signature, sign_card
from ellingson_card.trust import FULCIO_OIDC_ISSUER_OID, TrustRoot
from ellingson_card.verifier import verify_card
from tests.conftest import key_usage

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CARD = {"name": "a", "version": "1", "skills": [{"id": "s"}]}


def _signed(identity=IDENTITY):
    key, cert = generate_signing_material(identity)
    return attach_signature(CARD, sign_card(CARD, key, cert))


def _ca_root():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fulcio-test-root")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _ca_signed(identity=IDENTITY, oidc_issuer=OIDC_ISSUER):
    root_key, root = _ca_root()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .add_extension(key_usage(digital_signature=True), critical=True)
    )
    if oidc_issuer is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(FULCIO_OIDC_ISSUER_OID, oidc_issuer.encode()), critical=False
        )
    leaf = builder.sign(root_key, hashes.SHA256())
    sig = sign_card(CARD, leaf_key, leaf)
    sig["header"]["x5c"] = cert_to_x5c(leaf)
    return attach_signature(CARD, sig), TrustRoot((root,))


def test_valid_local_card_verifies():
    result = verify_card(_signed(), expected_identity=IDENTITY, require_bundle=False)
    assert result.valid
    assert result.identity == IDENTITY
    assert result.rekor_log_index is None


def test_missing_signature_fails_closed():
    with pytest.raises(MissingSignature):
        verify_card(CARD, expected_identity=IDENTITY)


def test_tampered_payload_fails_closed():
    signed = _signed()
    signed["name"] = "tampered"
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY, require_bundle=False)


def test_wrong_identity_fails_pinning():
    with pytest.raises(IdentityMismatch):
        verify_card(
            _signed(),
            expected_identity="https://evil.example/workflow.yml@refs/heads/main",
            require_bundle=False,
        )


def test_bundleless_card_rejected_when_bundle_required():
    with pytest.raises(MissingRekorEntry, match="no Sigstore bundle"):
        verify_card(_signed(), expected_identity=IDENTITY)


def test_bundleless_card_passes_when_not_required():
    assert verify_card(_signed(), expected_identity=IDENTITY, require_bundle=False).valid


def test_malformed_cert_fails_closed():
    signed = _signed()
    signed["signatures"][0]["header"]["x5c"] = []
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_malformed_signature_field_fails_closed():
    signed = _signed()
    signed["signatures"][0]["signature"] = "!!!not-b64url!!!"
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_expired_card_fails_closed():
    with pytest.raises(CardExpired):
        verify_card(
            _signed(),
            expected_identity=IDENTITY,
            require_bundle=False,
            max_age=timedelta(seconds=0),
        )


def test_self_signed_rejected_when_trust_root_configured():
    _, root = _ca_root()
    with pytest.raises(UntrustedCertificate):
        verify_card(
            _signed(),
            expected_identity=IDENTITY,
            require_bundle=False,
            trust_root=TrustRoot((root,)),
            expected_oidc_issuer=OIDC_ISSUER,
        )


def test_trust_root_without_expected_oidc_issuer_is_rejected():
    signed, trust_root = _ca_signed()
    with pytest.raises(ValueError, match="expected_oidc_issuer"):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_bundle=False,
            trust_root=trust_root,
        )


def test_ca_issued_cert_verifies_against_trust_root():
    signed, trust_root = _ca_signed()
    result = verify_card(
        signed,
        expected_identity=IDENTITY,
        require_bundle=False,
        trust_root=trust_root,
        expected_oidc_issuer=OIDC_ISSUER,
    )
    assert result.valid


def test_oidc_issuer_absent_rejected():
    signed, trust_root = _ca_signed(oidc_issuer=None)
    with pytest.raises(UntrustedCertificate, match="got None"):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_bundle=False,
            trust_root=trust_root,
            expected_oidc_issuer=OIDC_ISSUER,
        )


def test_oidc_issuer_mismatch_rejected():
    signed, trust_root = _ca_signed(oidc_issuer="https://evil.example")
    with pytest.raises(UntrustedCertificate, match="OIDC issuer"):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_bundle=False,
            trust_root=trust_root,
            expected_oidc_issuer=OIDC_ISSUER,
        )


def _bundle_signed(bundle="{}"):
    key, cert = generate_signing_material(IDENTITY)
    sig = sign_card(CARD, key, cert)
    sig["header"]["sigstoreBundle"] = bundle
    return attach_signature(CARD, sig), cert


def test_bundle_card_routes_to_sigstore_verify(monkeypatch):
    import ellingson_card.keyless_verify as kv

    signed, cert = _bundle_signed()
    captured = {}

    def fake_verify_bundle(message, bundle_json, **kwargs):
        captured.update(message=message, bundle_json=bundle_json, **kwargs)
        return 4581700

    monkeypatch.setattr(kv, "verify_bundle", fake_verify_bundle)
    result = verify_card(
        signed, expected_identity=IDENTITY, expected_oidc_issuer=OIDC_ISSUER, staging=True
    )
    assert result.rekor_log_index == 4581700
    assert captured["expected_identity"] == IDENTITY
    assert captured["staging"] is True
    assert captured["expected_leaf_der"] == cert.public_bytes(Encoding.DER)


def test_bundle_card_verified_even_when_bundle_required(monkeypatch):
    import ellingson_card.keyless_verify as kv

    signed, _ = _bundle_signed()
    monkeypatch.setattr(kv, "verify_bundle", lambda *_a, **_k: 1)
    assert verify_card(
        signed, expected_identity=IDENTITY, expected_oidc_issuer=OIDC_ISSUER, require_bundle=True
    ).valid


def test_bundle_card_without_issuer_is_rejected():
    signed, _ = _bundle_signed()
    with pytest.raises(ValueError, match="expected_oidc_issuer"):
        verify_card(signed, expected_identity=IDENTITY)


def test_bundle_card_forwards_expected_issuer(monkeypatch):
    import ellingson_card.keyless_verify as kv

    signed, _ = _bundle_signed()
    captured = {}

    def fake_verify_bundle(_message, _bundle_json, **kwargs):
        captured.update(kwargs)
        return 1

    monkeypatch.setattr(kv, "verify_bundle", fake_verify_bundle)
    verify_card(signed, expected_identity=IDENTITY, expected_oidc_issuer=OIDC_ISSUER)
    assert captured["expected_issuer"] == OIDC_ISSUER


def test_bundle_card_freshness_checked_before_sigstore(monkeypatch):
    import ellingson_card.keyless_verify as kv

    signed, _ = _bundle_signed()

    def explode(*_a, **_k):
        raise AssertionError("verify_bundle must not run for an expired card")

    monkeypatch.setattr(kv, "verify_bundle", explode)
    with pytest.raises(CardExpired):
        verify_card(signed, expected_identity=IDENTITY, max_age=timedelta(seconds=0))


def test_bundle_card_propagates_bundle_error(monkeypatch):
    import ellingson_card.keyless_verify as kv

    signed, _ = _bundle_signed()

    def boom(*_a, **_k):
        raise BundleVerificationError("inclusion proof does not bind")

    monkeypatch.setattr(kv, "verify_bundle", boom)
    with pytest.raises(BundleVerificationError):
        verify_card(signed, expected_identity=IDENTITY, expected_oidc_issuer=OIDC_ISSUER)


def test_bundle_card_with_non_string_header_fails_closed():
    signed, _ = _bundle_signed()
    signed["signatures"][0]["header"]["sigstoreBundle"] = {"not": "a string"}
    with pytest.raises(BundleVerificationError, match="must be a string"):
        verify_card(signed, expected_identity=IDENTITY, expected_oidc_issuer=OIDC_ISSUER)


def test_bundle_card_tampered_payload_fails_before_sigstore():
    signed, _ = _bundle_signed()
    signed["name"] = "tampered"
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_bundle_card_wrong_identity_fails_before_sigstore():
    signed, _ = _bundle_signed()
    with pytest.raises(IdentityMismatch):
        verify_card(signed, expected_identity="https://evil.example/wf.yml@refs/heads/main")
