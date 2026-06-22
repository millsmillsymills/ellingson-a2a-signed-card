from pathlib import Path

import pytest

from ellingson_card.card import CardError, card_for_signing, load_card

CARD_PATH = Path(__file__).parent.parent / "cards" / "ellingson-agent-card.json"


def test_canonical_card_loads_and_is_v1():
    card = load_card(CARD_PATH)
    assert card["supportedInterfaces"]
    iface = card["supportedInterfaces"][0]
    assert iface["protocolVersion"] == "1.0"
    assert iface["url"].startswith("https://")
    assert card["securitySchemes"]
    assert card["skills"]


def test_card_for_signing_drops_signatures():
    card = load_card(CARD_PATH)
    card["signatures"] = [{"protected": "x", "signature": "y"}]
    signing_view = card_for_signing(card)
    assert "signatures" not in signing_view
    assert "signatures" in card  # original untouched


def test_load_rejects_missing_required_field(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"name": "x"}')
    with pytest.raises(CardError):
        load_card(bad)


def test_load_rejects_plaintext_interface(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"name":"x","description":"d","version":"1","skills":[{"id":"s"}],'
        '"securitySchemes":{"o":{}},'
        '"supportedInterfaces":[{"url":"http://x","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}'
    )
    with pytest.raises(CardError):
        load_card(bad)
