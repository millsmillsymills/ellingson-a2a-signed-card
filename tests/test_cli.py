import json
from pathlib import Path

from ellingson_card.cli import main

CARD_PATH = Path(__file__).parent.parent / "cards" / "ellingson-agent-card.json"
IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"


def test_sign_then_verify_roundtrip(tmp_path, capsys):
    out = tmp_path / "signed.json"
    assert main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY]) == 0
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY, "--no-require-rekor"])
    assert rc == 0
    assert IDENTITY in capsys.readouterr().out


def test_verify_tampered_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    card = json.loads(out.read_text())
    card["name"] = "tampered"
    out.write_text(json.dumps(card))
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY, "--no-require-rekor"])
    assert rc != 0
    assert "BadSignature" in capsys.readouterr().err


def test_verify_wrong_identity_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    wrong = "https://evil.example/x@main"
    rc = main(["verify", "--in", str(out), "--identity", wrong, "--no-require-rekor"])
    assert rc != 0
    assert "IdentityMismatch" in capsys.readouterr().err
