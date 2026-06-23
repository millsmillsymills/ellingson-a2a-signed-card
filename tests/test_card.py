from pathlib import Path

import pytest

from ellingson_card.card import CardError, card_for_signing, load_card, read_card

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


def test_read_card_missing_file_message(tmp_path):
    with pytest.raises(CardError, match="cannot read card"):
        read_card(tmp_path / "absent.json")


def test_read_card_malformed_json_message(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(CardError, match="invalid card JSON"):
        read_card(bad)


@pytest.mark.parametrize("payload", ["[]", '"x"', "42", "null"])
def test_read_card_non_object_message(tmp_path, payload):
    bad = tmp_path / "scalar.json"
    bad.write_text(payload)
    with pytest.raises(CardError, match="card must be a JSON object"):
        read_card(bad)


def test_load_rejects_plaintext_interface(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"name":"x","description":"d","version":"1","skills":[{"id":"s"}],'
        '"securitySchemes":{"o":{}},'
        '"supportedInterfaces":[{"url":"http://x","protocolBinding":"JSONRPC","protocolVersion":"1.0"}]}'
    )
    with pytest.raises(CardError):
        load_card(bad)
