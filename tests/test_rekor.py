import base64
import json
import urllib.error
from email.message import Message

import pytest

from ellingson_card import rekor

ARTIFACT_HEX = "a" * 64
SIG_DER = b"\x30\x44\x02\x20" + b"\x01" * 32 + b"\x02\x20" + b"\x02" * 32


def _body(kind="hashedrekord", artifact_hex=ARTIFACT_HEX, sig_der=SIG_DER):
    return {
        "kind": kind,
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": artifact_hex}},
            "signature": {"content": base64.b64encode(sig_der).decode()},
        },
    }


def _rekor_payload(body):
    return {
        "uuid123": {"logIndex": 42, "body": base64.b64encode(json.dumps(body).encode()).decode()}
    }


class _Resp:
    status = 200

    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_urlopen(monkeypatch, payload=None, exc=None):
    def fake_urlopen(url, timeout):  # noqa: ARG001
        if exc is not None:
            raise exc
        return _Resp(payload)

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)


def test_fetch_entry_body_decodes(monkeypatch):
    _patch_urlopen(monkeypatch, _rekor_payload(_body()))
    body = rekor.fetch_entry_body(42)
    assert body is not None
    assert body["kind"] == "hashedrekord"


def test_fetch_entry_body_none_on_404(monkeypatch):
    _patch_urlopen(monkeypatch, exc=urllib.error.HTTPError("u", 404, "not found", Message(), None))
    assert rekor.fetch_entry_body(42) is None


def test_fetch_entry_body_network_error_propagates(monkeypatch):
    _patch_urlopen(monkeypatch, exc=urllib.error.URLError("down"))
    with pytest.raises(urllib.error.URLError):
        rekor.fetch_entry_body(42)


def test_fetch_entry_body_none_on_non_200(monkeypatch):
    class _ErrResp(_Resp):
        status = 500

    def fake_urlopen(url, timeout):  # noqa: ARG001
        return _ErrResp({})

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    assert rekor.fetch_entry_body(42) is None


def test_fetch_entry_body_propagates_non_404_http_error(monkeypatch):
    _patch_urlopen(monkeypatch, exc=urllib.error.HTTPError("u", 500, "boom", Message(), None))
    with pytest.raises(urllib.error.HTTPError):
        rekor.fetch_entry_body(42)


def test_fetch_entry_body_none_on_malformed_json(monkeypatch):
    class _BadResp(_Resp):
        def read(self):
            return b"this is not json"

    def fake_urlopen(url, timeout):  # noqa: ARG001
        return _BadResp(None)

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    assert rekor.fetch_entry_body(42) is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"uuid": "not-a-dict"},
        {"uuid": {}},
        {"uuid": {"body": 123}},
        {"uuid": {"body": "!!!not-base64!!!"}},
        {"uuid": {"body": base64.b64encode(json.dumps([1, 2]).encode()).decode()}},
    ],
)
def test_fetch_entry_body_none_on_malformed_payload(monkeypatch, payload):
    _patch_urlopen(monkeypatch, payload)
    assert rekor.fetch_entry_body(42) is None


def test_entry_binds_true_on_match():
    assert rekor.entry_binds(_body(), artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_hash_mismatch():
    body = _body(artifact_hex="b" * 64)
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_signature_mismatch():
    body = _body(sig_der=b"\x30\x06\x02\x01\x09\x02\x01\x09")
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_wrong_kind():
    body = _body(kind="dsse")
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_malformed_spec():
    assert not rekor.entry_binds(
        {"kind": "hashedrekord", "spec": "nope"},
        artifact_sha256_hex=ARTIFACT_HEX,
        signature_der=SIG_DER,
    )


def test_entry_binds_false_on_non_str_signature_content():
    body = _body()
    body["spec"]["signature"]["content"] = 123
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_malformed_signature_base64():
    body = _body()
    body["spec"]["signature"]["content"] = "!!!not-base64!!!"
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_non_dict_nested_field():
    body = {"kind": "hashedrekord", "spec": {"data": "notdict"}}
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)
