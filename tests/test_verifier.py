import base64
from datetime import timedelta

import pytest

import ellingson_card.verifier as verifier_mod
from ellingson_card.errors import (
    BadSignature,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
)
from ellingson_card.keys import generate_signing_material
from ellingson_card.rekor import entry_binds
from ellingson_card.signer import attach_signature, sign_card
from ellingson_card.verifier import verify_card

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"
CARD = {"name": "a", "version": "1", "skills": [{"id": "s"}]}


def _signed(identity=IDENTITY, rekor_log_index=None):
    key, cert = generate_signing_material(identity)
    sig = sign_card(CARD, key, cert, rekor_log_index=rekor_log_index)
    return attach_signature(CARD, sig)


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
        "spec": {
            "data": {"hash": {"value": captured["hex"]}},
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
