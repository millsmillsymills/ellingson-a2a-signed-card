import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from ellingson_card.cli import main
from tests.test_verifier import OIDC_ISSUER, _ca_signed, _self_signed_no_uri_san

CARD_PATH = Path(__file__).parent.parent / "cards" / "ellingson-agent-card.json"
IDENTITY = "https://github.com/ellingson/signed-card/.github/workflows/sign.yml@refs/heads/main"


def test_sign_then_verify_roundtrip(tmp_path, capsys):
    out = tmp_path / "signed.json"
    assert main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY]) == 0
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY, "--no-require-bundle"])
    assert rc == 0
    assert IDENTITY in capsys.readouterr().out


def test_verify_tampered_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    card = json.loads(out.read_text())
    card["name"] = "tampered"
    out.write_text(json.dumps(card))
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY, "--no-require-bundle"])
    assert rc != 0
    assert "BadSignature" in capsys.readouterr().err


def test_verify_wrong_identity_exits_nonzero(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    wrong = "https://evil.example/x@main"
    rc = main(["verify", "--in", str(out), "--identity", wrong, "--no-require-bundle"])
    assert rc != 0
    assert "IdentityMismatch" in capsys.readouterr().err


def test_verify_cert_without_uri_san_fails_closed(tmp_path, capsys):
    out = tmp_path / "nosan.json"
    out.write_text(json.dumps(_self_signed_no_uri_san()))
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY, "--no-require-bundle"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert err.startswith("IdentityMismatch: ")


def test_sign_missing_card_file_errors_cleanly(tmp_path, capsys):
    missing = tmp_path / "absent.json"
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(missing), "--out", str(out), "--identity", IDENTITY])
    assert rc == 1
    assert "cannot read card" in capsys.readouterr().err
    assert not out.exists()


def test_sign_malformed_card_errors_cleanly(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(bad), "--out", str(out), "--identity", IDENTITY])
    assert rc == 1
    assert "invalid card JSON" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize(
    ("payload", "type_name"),
    [("[]", "list"), ('"x"', "str"), ("42", "int"), ("null", "NoneType")],
)
def test_sign_non_object_card_errors_cleanly(tmp_path, capsys, payload, type_name):
    bad = tmp_path / "scalar.json"
    bad.write_text(payload)
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(bad), "--out", str(out), "--identity", IDENTITY])
    assert rc == 1
    assert capsys.readouterr().err.strip() == f"card must be a JSON object, got {type_name}"
    assert not out.exists()


def _write_anchored(tmp_path):
    signed, trust_root = _ca_signed()
    card = tmp_path / "anchored.json"
    card.write_text(json.dumps(signed))
    root = tmp_path / "root.pem"
    root.write_bytes(trust_root.anchors[0].public_bytes(Encoding.PEM))
    return card, root


def test_verify_bundleless_card_requires_bundle_by_default(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY])
    assert rc != 0
    assert "MissingRekorEntry" in capsys.readouterr().err


def test_verify_staging_with_trust_root_is_rejected(tmp_path, capsys):
    card, root = _write_anchored(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "verify",
                "--in",
                str(card),
                "--identity",
                IDENTITY,
                "--staging",
                "--trust-root",
                str(root),
                "--oidc-issuer",
                OIDC_ISSUER,
            ]
        )
    assert exc.value.code == 2
    assert "cannot be combined" in capsys.readouterr().err


@pytest.mark.parametrize(("flag", "expected"), [(["--staging"], True), ([], False)])
def test_sign_keyless_forwards_staging(tmp_path, monkeypatch, flag, expected):
    from ellingson_card import keyless as keyless_mod

    captured = {}

    def fake_keyless(card, *, staging):
        captured["staging"] = staging
        return {"protected": "x", "signature": "y", "header": {}}

    monkeypatch.setattr(keyless_mod, "sign_card_keyless", fake_keyless)
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--keyless", *flag])
    assert rc == 0
    assert captured["staging"] is expected


def test_verify_anchored_against_trust_root(tmp_path, capsys):
    card, root = _write_anchored(tmp_path)
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
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
            "--no-require-bundle",
            "--trust-root",
            str(root),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc != 0
    assert "has no extended key usage" in capsys.readouterr().err


def test_verify_wrong_oidc_issuer_rejected(tmp_path, capsys):
    card, root = _write_anchored(tmp_path)
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
            "--trust-root",
            str(root),
            "--oidc-issuer",
            "https://wrong-issuer.example",
        ]
    )
    assert rc != 0
    assert "UntrustedCertificate" in capsys.readouterr().err


def test_trust_root_without_oidc_issuer_errors(tmp_path, capsys):
    card, root = _write_anchored(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        main(["verify", "--in", str(card), "--identity", IDENTITY, "--trust-root", str(root)])
    assert excinfo.value.code == 2
    assert "--trust-root requires --oidc-issuer" in capsys.readouterr().err


def test_oidc_issuer_without_trust_root_is_allowed(tmp_path, capsys):
    card, _ = _write_anchored(tmp_path)
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc == 0
    assert IDENTITY in capsys.readouterr().out


def test_verify_missing_trust_root_file_errors_cleanly(tmp_path, capsys):
    card, _ = _write_anchored(tmp_path)
    missing = tmp_path / "absent.pem"
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
            "--trust-root",
            str(missing),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc == 1
    assert "cannot read trust root" in capsys.readouterr().err


def test_verify_malformed_trust_root_pem_errors_cleanly(tmp_path, capsys):
    card, _ = _write_anchored(tmp_path)
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate\n")
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
            "--trust-root",
            str(junk),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc == 1
    assert "invalid trust-root PEM" in capsys.readouterr().err


def test_verify_certless_trust_root_bundle_errors_cleanly(tmp_path, capsys):
    card, _ = _write_anchored(tmp_path)
    certless = tmp_path / "certless.pem"
    certless.write_text("# comment only, no certificates\n")
    rc = main(
        [
            "verify",
            "--in",
            str(card),
            "--identity",
            IDENTITY,
            "--no-require-bundle",
            "--trust-root",
            str(certless),
            "--oidc-issuer",
            OIDC_ISSUER,
        ]
    )
    assert rc == 1
    assert "invalid trust-root PEM" in capsys.readouterr().err


def test_verify_malformed_card_json_errors_cleanly(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    rc = main(["verify", "--in", str(bad), "--identity", IDENTITY, "--no-require-bundle"])
    assert rc == 1
    assert "invalid card JSON" in capsys.readouterr().err


def test_verify_missing_card_file_errors_cleanly(tmp_path, capsys):
    missing = tmp_path / "absent.json"
    rc = main(["verify", "--in", str(missing), "--identity", IDENTITY, "--no-require-bundle"])
    assert rc == 1
    assert "cannot read card" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("payload", "type_name"),
    [("[]", "list"), ('"x"', "str"), ("42", "int"), ("null", "NoneType")],
)
def test_verify_non_object_card_errors_cleanly(tmp_path, capsys, payload, type_name):
    bad = tmp_path / "scalar.json"
    bad.write_text(payload)
    rc = main(["verify", "--in", str(bad), "--identity", IDENTITY, "--no-require-bundle"])
    assert rc == 1
    assert capsys.readouterr().err.strip() == f"card must be a JSON object, got {type_name}"


@pytest.mark.parametrize(
    ("signatures", "error_name"),
    [
        ('{"signatures": 5}', "BadSignature"),
        ('{"signatures": "x"}', "BadSignature"),
        ('{"signatures": [1]}', "BadSignature"),
        ('{"signatures": []}', "MissingSignature"),
    ],
)
def test_verify_malformed_signatures_fail_closed(tmp_path, capsys, signatures, error_name):
    bad = tmp_path / "card.json"
    bad.write_text(signatures)
    rc = main(["verify", "--in", str(bad), "--identity", IDENTITY, "--no-require-bundle"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert err.startswith(f"{error_name}: ")


@pytest.mark.parametrize(
    "content",
    [None, "{not json", "null"],
    ids=["missing", "malformed-json", "non-object"],
)
def test_sign_and_verify_emit_identical_stderr(tmp_path, capsys, content):
    bad = tmp_path / "card.json"
    if content is not None:
        bad.write_text(content)
    out = tmp_path / "signed.json"

    sign_rc = main(["sign", "--in", str(bad), "--out", str(out), "--identity", IDENTITY])
    sign_err = capsys.readouterr().err
    verify_rc = main(["verify", "--in", str(bad), "--identity", IDENTITY, "--no-require-bundle"])
    verify_err = capsys.readouterr().err

    assert sign_rc == 1
    assert verify_rc == 1
    assert sign_err.strip()
    assert sign_err == verify_err
