import json
import os
import signal
import socket
import subprocess
import sys
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


def test_verify_bundle_card_without_oidc_issuer_errors_cleanly(tmp_path, capsys):
    out = tmp_path / "signed.json"
    main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    card = json.loads(out.read_text())
    card["signatures"][0]["header"]["sigstoreBundle"] = "{}"
    out.write_text(json.dumps(card))
    rc = main(["verify", "--in", str(out), "--identity", IDENTITY])
    assert rc == 1
    assert "expected_oidc_issuer is required" in capsys.readouterr().err


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


def test_sign_out_path_in_missing_directory_errors_cleanly(tmp_path, capsys):
    out = tmp_path / "no-such-dir" / "signed.json"
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert f"cannot write signed card {out}" in err
    assert not out.exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="chmod has no effect as root")
def test_sign_out_path_in_readonly_directory_errors_cleanly(tmp_path, capsys):
    readonly = tmp_path / "readonly"
    readonly.mkdir()
    readonly.chmod(0o500)
    out = readonly / "signed.json"
    try:
        rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    finally:
        readonly.chmod(0o755)
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert f"cannot write signed card {out}" in err
    assert not out.exists()


def test_sign_out_path_is_directory_errors_cleanly(tmp_path, capsys):
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(tmp_path), "--identity", IDENTITY])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert f"cannot write signed card {tmp_path}" in err


def test_sign_write_failure_mid_write_leaves_target_untouched(tmp_path, capsys, monkeypatch):
    out = tmp_path / "signed.json"
    out.write_text("previous signed card")

    def partial_write_then_enospc(self, text, *args, **kwargs):
        with self.open("w") as fh:
            fh.write(text[:10])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_text", partial_write_then_enospc)
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert f"cannot write signed card {out}" in err
    assert out.read_text() == "previous signed card"
    assert list(tmp_path.iterdir()) == [out]


def test_sign_success_leaves_only_the_signed_card(tmp_path):
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    assert rc == 0
    assert list(tmp_path.iterdir()) == [out]


def test_sign_over_existing_target_replaces_content(tmp_path):
    out = tmp_path / "signed.json"
    out.write_text("stale signed card")
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    assert rc == 0
    signed = json.loads(out.read_text())
    assert signed["signatures"]
    assert list(tmp_path.iterdir()) == [out]


def test_sign_does_not_clobber_unrelated_tmp_file(tmp_path):
    out = tmp_path / "signed.json"
    bystander = tmp_path / "signed.json.tmp"
    bystander.write_text("unrelated file")
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--identity", IDENTITY])
    assert rc == 0
    assert bystander.read_text() == "unrelated file"
    assert sorted(tmp_path.iterdir()) == [out, bystander]


def test_sign_empty_required_field_errors_cleanly(tmp_path, capsys):
    bad = tmp_path / "empty-skills.json"
    bad.write_text(
        '{"name":"x","description":"d","version":"1","skills":[],'
        '"securitySchemes":{"o":{}},'
        '"supportedInterfaces":[{"url":"https://x","protocolVersion":"1.0"}]}'
    )
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(bad), "--out", str(out), "--identity", IDENTITY])
    assert rc == 1
    assert "present but empty: skills" in capsys.readouterr().err
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


def test_serve_missing_card_errors_cleanly(tmp_path, capsys):
    rc = main(["serve", "--card", str(tmp_path / "absent.json"), "--port", "0"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert "cannot read card" in err


@pytest.mark.skipif(os.geteuid() == 0, reason="chmod has no effect as root")
def test_serve_unreadable_card_errors_cleanly(tmp_path, capsys):
    card = tmp_path / "card.json"
    card.write_text("{}")
    card.chmod(0o000)
    try:
        rc = main(["serve", "--card", str(card), "--port", "0"])
    finally:
        card.chmod(0o644)
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert "cannot read card" in err


def test_serve_taken_port_errors_cleanly(tmp_path, capsys):
    card = tmp_path / "card.json"
    card.write_text("{}")
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        port = taken.getsockname()[1]
        rc = main(["serve", "--card", str(card), "--port", str(port)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert f"cannot bind 127.0.0.1:{port}" in err


def test_serve_keyboard_interrupt_exits_cleanly(tmp_path, capsys, monkeypatch):
    from ellingson_card import cli as cli_mod

    class _FakeServer:
        server_address = ("127.0.0.1", 12345)
        closed = False

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            self.closed = True

    fake = _FakeServer()
    monkeypatch.setattr(cli_mod, "make_server", lambda path, port: fake)
    rc = main(["serve", "--card", str(tmp_path / "any.json"), "--port", "0"])
    assert rc == 130
    assert fake.closed


def test_serve_sigterm_exits_cleanly(tmp_path, monkeypatch):
    from ellingson_card import cli as cli_mod

    class _FakeServer:
        server_address = ("127.0.0.1", 12345)
        closed = False

        def serve_forever(self):
            os.kill(os.getpid(), signal.SIGTERM)

        def server_close(self):
            self.closed = True

    fake = _FakeServer()
    monkeypatch.setattr(cli_mod, "make_server", lambda path, port: fake)
    previous_handler = signal.getsignal(signal.SIGTERM)
    rc = main(["serve", "--card", str(tmp_path / "any.json"), "--port", "0"])
    assert rc == 143
    assert fake.closed
    assert signal.getsignal(signal.SIGTERM) is previous_handler


def test_serve_sigterm_subprocess_exits_143(tmp_path):
    card = tmp_path / "card.json"
    card.write_text("{}")
    argv = [sys.executable, "-u", "-m", "ellingson_card.cli", "serve", "--card", str(card)]
    proc = subprocess.Popen(
        [*argv, "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.readline().startswith("serving ")
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 143
    finally:
        proc.kill()


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


def test_sign_keyless_without_credential_errors_cleanly(tmp_path, capsys, monkeypatch):
    import sigstore.oidc

    monkeypatch.setattr(sigstore.oidc, "detect_credential", lambda: None)
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--keyless"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert "no ambient OIDC credential; run in a CI job with id-token: write" in err
    assert not out.exists()


def test_sign_keyless_sigstore_failure_errors_cleanly(tmp_path, capsys, monkeypatch):
    from ellingson_card import keyless as keyless_mod
    from ellingson_card.errors import SigningError

    def boom(card, *, staging):
        raise SigningError("Sigstore keyless signing failed: fulcio unreachable")

    monkeypatch.setattr(keyless_mod, "sign_card_keyless", boom)
    out = tmp_path / "signed.json"
    rc = main(["sign", "--in", str(CARD_PATH), "--out", str(out), "--keyless"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "Traceback" not in err
    assert err.strip() == "Sigstore keyless signing failed: fulcio unreachable"
    assert not out.exists()


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
