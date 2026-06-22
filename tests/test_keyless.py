import sigstore.oidc

import ellingson_card.keyless as keyless


def test_keyless_requires_ambient_credential(monkeypatch):
    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: None)
    try:
        keyless.sign_card_keyless({"name": "a"})
    except RuntimeError as exc:
        assert "OIDC" in str(exc)
    else:
        raise AssertionError("expected RuntimeError when no ambient credential")
