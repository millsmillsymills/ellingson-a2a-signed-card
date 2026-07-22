import pytest
import sigstore.oidc

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
