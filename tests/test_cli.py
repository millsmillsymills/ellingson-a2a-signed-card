import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from ellingson_card.cli import main
from tests.test_verifier import OIDC_ISSUER, _ca_signed

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


def _write_anchored(tmp_path):
    signed, trust_root = _ca_signed()
    card = tmp_path / "anchored.json"
    card.write_text(json.dumps(signed))
    root = tmp_path / "root.pem"
    root.write_bytes(trust_root.anchors[0].public_bytes(Encoding.PEM))
    return card, root


def test_verify_anchored_against_trust_root(tmp_path, capsys):
    card, root = _write_anchored(tmp_path)
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-rekor",
            "--trust-root",
            str(root),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc == 0
    assert IDENTITY in capsys.readouterr().out


def test_verify_self_signed_rejected_under_trust_root(tmp_path, capsys):
    _, root = _write_anchored(tmp_path)
    out = tmp_path / "selfsigned.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    rc = main(
        [
            "verify",
            "--in",
            str(out),
            "--identity",
            IDENTITY,
            "--no-require-rekor",
            "--trust-root",
            str(root),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc != 0
    assert "UntrustedCertificate" in capsys.readouterr().err


def test_trust_root_without_oidc_issuer_errors(tmp_path):
    card, root = _write_anchored(tmp_path)
    with pytest.raises(SystemExit):
        main(["verify", "--in", str(card), "--identity", IDENTITY, "--trust-root", str(root)])


def test_oidc_issuer_without_trust_root_errors(tmp_path):
    card, _ = _write_anchored(tmp_path)
    with pytest.raises(SystemExit):
        main(["verify", "--in", str(card), "--identity", IDENTITY, "--oidc-issuer", OIDC_ISSUER])
