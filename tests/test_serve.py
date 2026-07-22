import json
import threading
import urllib.error
import urllib.request

import pytest

from ellingson_card.serve import WELL_KNOWN_PATH, make_server


@pytest.fixture
def server_url(tmp_path):
    card = tmp_path / "signed-card.json"
    card.write_text(json.dumps({"name": "Ellingson", "signatures": [{"protected": "p"}]}))
    server = make_server(card, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_well_known_returns_card_with_security_headers(server_url):
    with urllib.request.urlopen(f"{server_url}{WELL_KNOWN_PATH}") as resp:
        body = json.loads(resp.read())
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "application/json"
        assert resp.headers["Strict-Transport-Security"]
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert body["name"] == "Ellingson"


def test_other_paths_404(server_url):
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{server_url}/nope")
    assert exc.value.code == 404


def test_head_well_known_matches_get_headers_with_empty_body(server_url):
    with urllib.request.urlopen(f"{server_url}{WELL_KNOWN_PATH}") as get_resp:
        get_body = get_resp.read()
        get_headers = get_resp.headers

    head_req = urllib.request.Request(f"{server_url}{WELL_KNOWN_PATH}", method="HEAD")
    with urllib.request.urlopen(head_req) as resp:
        assert resp.status == 200
        assert resp.headers["Content-Type"] == get_headers["Content-Type"]
        assert resp.headers["Content-Length"] == str(len(get_body))
        assert resp.headers["Strict-Transport-Security"] == get_headers["Strict-Transport-Security"]
        assert resp.headers["X-Content-Type-Options"] == get_headers["X-Content-Type-Options"]
        assert resp.read() == b""


def test_head_other_paths_404(server_url):
    head_req = urllib.request.Request(f"{server_url}/nope", method="HEAD")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(head_req)
    assert exc.value.code == 404
