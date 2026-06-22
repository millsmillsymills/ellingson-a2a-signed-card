import urllib.error
from email.message import Message

import pytest

from ellingson_card import rekor


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_entry_exists_true_on_200(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout):  # noqa: ARG001
        captured["url"] = url
        return _Resp()

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    assert rekor.rekor_entry_exists(42) is True
    assert "logIndex=42" in captured["url"]


def test_entry_exists_false_on_404(monkeypatch):
    def fake_urlopen(url, timeout):  # noqa: ARG001
        raise urllib.error.HTTPError(url, 404, "not found", Message(), None)

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    assert rekor.rekor_entry_exists(42) is False


def test_network_error_propagates(monkeypatch):
    def fake_urlopen(url, timeout):  # noqa: ARG001
        raise urllib.error.URLError("down")

    monkeypatch.setattr(rekor.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.URLError):
        rekor.rekor_entry_exists(42)
