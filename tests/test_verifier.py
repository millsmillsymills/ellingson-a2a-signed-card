from datetime import timedelta

import pytest

from ellingson_card.errors import (
    BadSignature,
    CardExpired,
    IdentityMismatch,
    MissingRekorEntry,
    MissingSignature,
)
from ellingson_card.keys import generate_signing_material
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
    result = verify_card(signed, expected_identity=IDENTITY, rekor_checker=lambda _index: True)
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
            rekor_checker=lambda _index: False,
        )


def test_expired_card_fails_closed():
    signed = _signed(rekor_log_index=7)
    with pytest.raises(CardExpired):
        verify_card(
            signed,
            expected_identity=IDENTITY,
            require_rekor=False,
            max_age=timedelta(seconds=0),
        )
