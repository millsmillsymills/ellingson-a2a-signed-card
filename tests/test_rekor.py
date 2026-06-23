import base64
import json
import logging
import urllib.error
from email.message import Message

import pytest

from ellingson_card import rekor

ARTIFACT_HEX = "a" * 64
SIG_DER = b"\x30\x44\x02\x20" + b"\x01" * 32 + b"\x02\x20" + b"\x02" * 32


def _body(
    kind="hashedrekord",
    artifact_hex=ARTIFACT_HEX,
    sig_der=SIG_DER,
    api_version="0.0.1",
    algorithm="sha256",
):
    return {
        "kind": kind,
        "apiVersion": api_version,
        "spec": {
            "data": {"hash": {"algorithm": algorithm, "value": artifact_hex}},
            "signature": {"content": base64.b64encode(sig_der).decode()},
        },
    }


def _rekor_payload(body, log_index=42):
    return {
        "uuid123": {
            "logIndex": log_index,
            "body": base64.b64encode(json.dumps(body).encode()).decode(),
        }
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


def test_fetch_entry_body_targets_base_url(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout):  # noqa: ARG001
        captured["url"] = url
        return _Resp(_rekor_payload(_body()))

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    rekor.fetch_entry_body(42, base_url=rekor.STAGING_REKOR_URL)
    assert captured["url"].startswith(rekor.STAGING_REKOR_URL)


def test_fetch_entry_body_none_on_index_mismatch(monkeypatch):
    _patch_urlopen(monkeypatch, _rekor_payload(_body(), log_index=99))
    assert rekor.fetch_entry_body(42) is None


def test_fetch_entry_body_none_on_missing_index(monkeypatch):
    payload = _rekor_payload(_body())
    del payload["uuid123"]["logIndex"]
    _patch_urlopen(monkeypatch, payload)
    assert rekor.fetch_entry_body(42) is None


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
        {"kind": "hashedrekord", "apiVersion": "0.0.1", "spec": "nope"},
        artifact_sha256_hex=ARTIFACT_HEX,
        signature_der=SIG_DER,
    )


def test_entry_binds_false_on_v002_shaped_body():
    body = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.2",
        "spec": {
            "hashedRekordV002": {
                "data": {"algorithm": "SHA2_256", "digest": ARTIFACT_HEX},
                "signature": {"content": base64.b64encode(SIG_DER).decode()},
            }
        },
    }
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_non_str_signature_content():
    body = _body()
    body["spec"]["signature"]["content"] = 123
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_malformed_signature_base64():
    body = _body()
    body["spec"]["signature"]["content"] = "!!!not-base64!!!"
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_non_dict_nested_field():
    body = {"kind": "hashedrekord", "apiVersion": "0.0.1", "spec": {"data": "notdict"}}
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_non_sha256_algorithm():
    body = _body(algorithm="sha512")
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_missing_algorithm():
    body = _body()
    del body["spec"]["data"]["hash"]["algorithm"]
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_unsupported_apiversion():
    body = _body(api_version="0.0.2")
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def test_entry_binds_false_on_missing_apiversion():
    body = _body()
    del body["apiVersion"]
    assert not rekor.entry_binds(body, artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)


def _records_at(caplog, level):
    return [r for r in caplog.records if r.levelno == level and r.name == rekor.__name__]


def test_entry_binds_logs_warning_on_hash_mismatch(caplog):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    rekor.entry_binds(
        _body(artifact_hex="b" * 64), artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER
    )
    assert _records_at(caplog, logging.WARNING)


def test_entry_binds_logs_warning_on_signature_mismatch(caplog):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    rekor.entry_binds(
        _body(sig_der=b"\x30\x06\x02\x01\x09\x02\x01\x09"),
        artifact_sha256_hex=ARTIFACT_HEX,
        signature_der=SIG_DER,
    )
    assert _records_at(caplog, logging.WARNING)


def test_entry_binds_logs_debug_on_structural_surprise(caplog):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    rekor.entry_binds(_body(kind="dsse"), artifact_sha256_hex=ARTIFACT_HEX, signature_der=SIG_DER)
    assert _records_at(caplog, logging.DEBUG)
    assert not _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_debug_on_404(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    _patch_urlopen(monkeypatch, exc=urllib.error.HTTPError("u", 404, "not found", Message(), None))
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.DEBUG)
    assert not _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_warning_on_non_200(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)

    class _ErrResp(_Resp):
        status = 500

    monkeypatch.setattr(rekor.urllib.request, "urlopen", lambda url, timeout: _ErrResp({}))
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_warning_on_index_mismatch(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    _patch_urlopen(monkeypatch, _rekor_payload(_body(), log_index=99))
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_warning_on_missing_index(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    payload = _rekor_payload(_body())
    del payload["uuid123"]["logIndex"]
    _patch_urlopen(monkeypatch, payload)
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_debug_on_missing_body(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    payload = _rekor_payload(_body())
    del payload["uuid123"]["body"]
    _patch_urlopen(monkeypatch, payload)
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.DEBUG)
    assert not _records_at(caplog, logging.WARNING)


def test_fetch_entry_body_logs_warning_on_bad_base64_body(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG, logger=rekor.__name__)
    _patch_urlopen(monkeypatch, {"uuid": {"logIndex": 42, "body": "!!!not-base64!!!"}})
    rekor.fetch_entry_body(42)
    assert _records_at(caplog, logging.WARNING)
