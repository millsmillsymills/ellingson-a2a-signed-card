import base64
import logging
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import ellingson_card.verifier as verifier_mod
from ellingson_card.errors import (
    BadSignature,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
    UntrustedCertificate,
)
from ellingson_card.keys import cert_to_x5c, generate_signing_material
from ellingson_card.rekor import entry_binds
from ellingson_card.signer import attach_signature, sign_card
from ellingson_card.trust import FULCIO_OIDC_ISSUER_OID, TrustRoot
from ellingson_card.verifier import verify_card

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CARD = {"name": "a", "version": "1", "skills": [{"id": "s"}]}


def _signed(identity=IDENTITY, rekor_log_index=None):
    key, cert = generate_signing_material(identity)
    sig = sign_card(CARD, key, cert, rekor_log_index=rekor_log_index)
    return attach_signature(CARD, sig)


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
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if oidc_issuer is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(FULCIO_OIDC_ISSUER_OID, oidc_issuer.encode()), critical=False
        )
    leaf = builder.sign(root_key, hashes.SHA256())
    sig = sign_card(CARD, leaf_key, leaf, rekor_log_index=None)
    sig["header"]["x5c"] = cert_to_x5c(leaf)
    return attach_signature(CARD, sig), TrustRoot((root,))


def test_valid_card_verifies():
    signed = _signed(rekor_log_index=7)
    result = verify_card(signed, expected_identity=IDENTITY, rekor_checker=lambda *_args: True)
    assert result.valid
    assert result.identity == IDENTITY
    assert result.rekor_log_index == 7


def test_missing_signature_fails_closed():
    with pytest.raises(MissingSignature):
        verify_card(CARD, expected_identity=IDENTITY)


def test_tampered_payload_fails_closed():
    signed = _signed(rekor_log_index=7)
    signed["name"] = "tampered"
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_wrong_identity_fails_pinning():
    signed = _signed(rekor_log_index=7)
    with pytest.raises(IdentityMismatch):
        verify_card(signed, expected_identity="https://evil.example/workflow.yml@refs/heads/main")


def test_missing_rekor_entry_fails_when_required():
    signed = _signed(rekor_log_index=None)
    with pytest.raises(MissingRekorEntry):
        verify_card(signed, expected_identity=IDENTITY, require_rekor=True)


def test_rekor_not_required_passes_without_entry():
    signed = _signed(rekor_log_index=None)
    assert verify_card(signed, expected_identity=IDENTITY, require_rekor=False).valid


def test_rekor_checker_rejection_fails_closed():
    signed = _signed(rekor_log_index=7)
    with pytest.raises(MissingRekorEntry):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=True,
            rekor_checker=lambda *_args: False,
        )


def test_rekor_checker_receives_binding_material():
    signed = _signed(rekor_log_index=7)
    captured = {}

    def checker(index, artifact_hex, signature_der):
        captured.update(index=index, hex=artifact_hex, der=signature_der)
        return True

    verify_card(signed, expected_identity=IDENTITY, rekor_checker=checker)
    assert captured["index"] == 7
    assert len(captured["hex"]) == 64
    matching_body = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": captured["hex"]}},
            "signature": {"content": base64.b64encode(captured["der"]).decode()},
        },
    }
    assert entry_binds(
        matching_body, artifact_sha256_hex=captured["hex"], signature_der=captured["der"]
    )


def test_default_checker_rejects_entry_bound_to_other_signature(monkeypatch):
    signed = _signed(rekor_log_index=7)
    unbound = {
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"value": "0" * 64}},
            "signature": {
                "content": base64.b64encode(b"\x30\x06\x02\x01\x09\x02\x01\x09").decode()
            },
        },
    }
    monkeypatch.setattr(verifier_mod, "fetch_entry_body", lambda *_a, **_k: unbound)
    with pytest.raises(MissingRekorEntry):
        verify_card(signed, expected_identity=IDENTITY)


def test_default_checker_rejects_when_entry_absent(monkeypatch):
    signed = _signed(rekor_log_index=7)
    monkeypatch.setattr(verifier_mod, "fetch_entry_body", lambda *_a, **_k: None)
    with pytest.raises(MissingRekorEntry):
        verify_card(signed, expected_identity=IDENTITY)


def test_default_checker_logs_debug_when_entry_absent(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=verifier_mod.__name__)
    monkeypatch.setattr(verifier_mod, "fetch_entry_body", lambda *_a, **_k: None)
    assert not verifier_mod.default_rekor_checker(7, "a" * 64, b"\x30\x06")
    records = [r for r in caplog.records if r.name == verifier_mod.__name__]
    assert any(r.levelno == logging.DEBUG for r in records)
    assert not any(r.levelno == logging.WARNING for r in records)


def test_default_checker_logs_warning_when_entry_does_not_bind(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger=verifier_mod.__name__)
    unbound = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": "0" * 64}},
            "signature": {
                "content": base64.b64encode(b"\x30\x06\x02\x01\x09\x02\x01\x09").decode()
            },
        },
    }
    monkeypatch.setattr(verifier_mod, "fetch_entry_body", lambda *_a, **_k: unbound)
    assert not verifier_mod.default_rekor_checker(7, "a" * 64, b"\x30\x44")
    records = [r for r in caplog.records if r.name == verifier_mod.__name__]
    assert any(r.levelno == logging.WARNING for r in records)


def test_non_int_rekor_index_fails_closed():
    signed = _signed(rekor_log_index=7)
    signed["signatures"][0]["header"]["rekorLogIndex"] = "7; DROP"
    with pytest.raises(MissingRekorEntry):
        verify_card(signed, expected_identity=IDENTITY, rekor_checker=lambda *_args: True)


def test_bool_rekor_index_fails_closed():
    signed = _signed(rekor_log_index=7)
    signed["signatures"][0]["header"]["rekorLogIndex"] = True
    with pytest.raises(MissingRekorEntry):
        verify_card(signed, expected_identity=IDENTITY, rekor_checker=lambda *_args: True)


def test_malformed_cert_fails_closed():
    signed = _signed(rekor_log_index=7)
    signed["signatures"][0]["header"]["x5c"] = []
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_malformed_signature_field_fails_closed():
    signed = _signed(rekor_log_index=7)
    signed["signatures"][0]["signature"] = "!!!not-b64url!!!"
    with pytest.raises(BadSignature):
        verify_card(signed, expected_identity=IDENTITY)


def test_expired_card_fails_closed():
    signed = _signed(rekor_log_index=7)
    with pytest.raises(CardExpired):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            max_age=timedelta(seconds=0),
        )


def test_self_signed_rejected_when_trust_root_configured():
    _, root = _ca_root()
    signed = _signed()
    with pytest.raises(UntrustedCertificate):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            trust_root=TrustRoot((root,)),
            expected_oidc_issuer=OIDC_ISSUER,
        )


def test_trust_root_without_expected_oidc_issuer_is_rejected():
    signed, trust_root = _ca_signed()
    with pytest.raises(ValueError, match="expected_oidc_issuer"):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            trust_root=trust_root,
        )


def test_ca_issued_cert_verifies_against_trust_root():
    signed, trust_root = _ca_signed()
    result = verify_card(
        signed,
        expected_identity=IDENTITY,
        require_rekor=False,
        trust_root=trust_root,
        expected_oidc_issuer=OIDC_ISSUER,
    )
    assert result.valid


def test_oidc_issuer_absent_rejected():
    signed, trust_root = _ca_signed(oidc_issuer=None)
    with pytest.raises(UntrustedCertificate):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            trust_root=trust_root,
            expected_oidc_issuer=OIDC_ISSUER,
        )


def test_oidc_issuer_mismatch_rejected():
    signed, trust_root = _ca_signed(oidc_issuer="https://evil.example")
    with pytest.raises(UntrustedCertificate):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            trust_root=trust_root,
            expected_oidc_issuer=OIDC_ISSUER,
        )


def test_local_demo_path_unchanged_without_trust_root():
    signed = _signed(rekor_log_index=7)
    result = verify_card(signed, expected_identity=IDENTITY, rekor_checker=lambda *_a: True)
    assert result.valid
