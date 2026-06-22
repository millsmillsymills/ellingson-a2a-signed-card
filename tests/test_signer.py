import base64
import json

from ellingson_card.keys import generate_signing_material
from ellingson_card.signer import attach_signature, sign_card

IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"
CARD = {"name": "a", "version": "1", "skills": [{"id": "s"}]}


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_signature_shape_is_spec_native():
    key, cert = generate_signing_material(IDENTITY)
    sig = sign_card(CARD, key, cert)
    assert set(sig) >= {"protected", "signature", "header"}
    assert json.loads(_b64url_decode(sig["protected"])) == {"alg": "ES256"}
    assert sig["header"]["x5c"]
    # ES256 raw signature is R||S = 64 bytes
    assert len(_b64url_decode(sig["signature"])) == 64


def test_rekor_log_index_included_only_when_present():
    key, cert = generate_signing_material(IDENTITY)
    assert "rekorLogIndex" not in sign_card(CARD, key, cert)["header"]
    assert sign_card(CARD, key, cert, rekor_log_index=42)["header"]["rekorLogIndex"] == 42


def test_attach_signature_sets_signatures_array():
    key, cert = generate_signing_material(IDENTITY)
    sig = sign_card(CARD, key, cert)
    signed = attach_signature(CARD, sig)
    assert signed["signatures"] == [sig]
    assert "signatures" not in CARD
