import pytest
import sigstore.oidc
import sigstore.sign

import ellingson_card.keyless as keyless
from ellingson_card.errors import SigningError


def test_keyless_requires_ambient_credential(monkeypatch):
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: None)
    with pytest.raises(SigningError, match="no ambient OIDC credential"):
        keyless.sign_card_keyless({"name": "a"})


def test_keyless_wraps_credential_detection_failure(monkeypatch):
    def boom():
        raise OSError("metadata service unreachable")

    monkeypatch.setattr(sigstore.oidc, "detect_credential", boom)
    with pytest.raises(SigningError, match="credential detection failed"):
        keyless.sign_card_keyless({"name": "a"})


def test_keyless_wraps_invalid_token(monkeypatch):
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: "not-a-jwt")
    with pytest.raises(SigningError, match="invalid ambient OIDC token"):
        keyless.sign_card_keyless({"name": "a"})


@pytest.mark.parametrize("staging", [False, True])
def test_keyless_wraps_sigstore_signing_failure(monkeypatch, staging):
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: "header.payload.sig")
    monkeypatch.setattr(sigstore.oidc, "IdentityToken", lambda raw: object())
    monkeypatch.setattr(sigstore.sign.ClientTrustConfig, "production", lambda: object())
    monkeypatch.setattr(sigstore.sign.ClientTrustConfig, "staging", lambda: object())

    original = ConnectionError("fulcio unreachable")

    def boom(trust):
        raise original

    monkeypatch.setattr(sigstore.sign.SigningContext, "from_trust_config", boom)
    with pytest.raises(SigningError, match="Sigstore keyless signing failed") as exc_info:
        keyless.sign_card_keyless({"name": "a"}, staging=staging)
    assert exc_info.value.__cause__ is original
