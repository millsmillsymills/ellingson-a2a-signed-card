import json
from pathlib import Path

import pytest

from ellingson_card.card import CardError, card_for_signing, load_card, read_card

CARD_PATH = Path(__file__).parent.parent / "cards" / "ellingson-agent-card.json"


def _write_card(tmp_path, **overrides):
    card = {
        "name": "x",
        "description": "d",
        "version": "1",
        "skills": [{"id": "s"}],
        "securitySchemes": {"o": {}},
        "supportedInterfaces": [{"url": "https://x", "protocolVersion": "1.0"}],
    }
    card.update(overrides)
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card))
    return path


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
    with pytest.raises(CardError, match="missing required field\\(s\\)") as excinfo:
        load_card(bad)
    assert "description" in str(excinfo.value)
    assert "empty" not in str(excinfo.value)


def test_load_reports_empty_array_field_as_empty_not_missing(tmp_path):
    bad = _write_card(tmp_path, skills=[])
    with pytest.raises(CardError, match="present but empty: skills") as excinfo:
        load_card(bad)
    assert "missing" not in str(excinfo.value)


def test_load_reports_empty_string_field_as_empty_not_missing(tmp_path):
    bad = _write_card(tmp_path, description="")
    with pytest.raises(CardError, match="present but empty: description") as excinfo:
        load_card(bad)
    assert "missing" not in str(excinfo.value)


def test_load_reports_whitespace_only_string_field_as_empty(tmp_path):
    bad = _write_card(tmp_path, description="   \t\n")
    with pytest.raises(CardError, match="present but empty: description") as excinfo:
        load_card(bad)
    assert "missing" not in str(excinfo.value)


def test_load_reports_nbsp_only_string_field_as_empty(tmp_path):
    bad = _write_card(tmp_path, description="\u00a0")
    with pytest.raises(CardError, match="present but empty: description") as excinfo:
        load_card(bad)
    assert "missing" not in str(excinfo.value)


def test_load_accepts_zwsp_only_string_field(tmp_path):
    # Zero-width characters are intentionally not treated as whitespace.
    card = _write_card(tmp_path, description="\u200b")
    assert load_card(card)["description"] == "\u200b"


def test_load_reports_missing_and_empty_fields_together(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"name": "", "skills": []}')
    with pytest.raises(CardError) as excinfo:
        load_card(bad)
    message = str(excinfo.value)
    assert "missing required field(s): description, version" in message
    assert "present but empty: name, skills" in message


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


def test_load_rejects_non_object_interface_entry(tmp_path):
    bad = _write_card(tmp_path, supportedInterfaces=["s"])
    with pytest.raises(CardError, match="interface entry must be an object"):
        load_card(bad)


def test_load_rejects_non_string_interface_url(tmp_path):
    bad = _write_card(tmp_path, supportedInterfaces=[{"url": 123}])
    with pytest.raises(CardError, match="interface url must be a string"):
        load_card(bad)


def test_load_rejects_plaintext_interface(tmp_path):
    bad = _write_card(
        tmp_path,
        supportedInterfaces=[
            {"url": "http://x", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
    )
    with pytest.raises(CardError):
        load_card(bad)
