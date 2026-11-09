"""The local web UI server: routing and the safety checks."""

import io
import json
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import pytest

from pqcscan.server import make_server

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


@pytest.fixture(scope="module")
def srv():
    httpd = make_server(port=0, token="t0k3n")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def req(url, data=None, headers=None, method=None):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_page_has_token_and_no_placeholders(srv):
    code, body = req(srv + "/")
    html = body.decode()
    assert code == 200 and 'const TOKEN = "t0k3n"' in html
    assert "{{" not in html


def test_wrong_host_is_rejected(srv):
    code, _ = req(srv + "/", headers={"Host": "attacker.example:80"})
    assert code == 403


def test_post_without_token_is_rejected(srv):
    code, _ = req(srv + "/api/scan/path", data=b'{"path": "."}', method="POST")
    assert code == 403


def test_scan_path(srv):
    code, body = req(srv + "/api/scan/path", data=json.dumps({"path": str(EXAMPLE)}).encode(),
                     headers={"X-Pqcscan-Token": "t0k3n"}, method="POST")
    data = json.loads(body)
    assert code == 200
    assert data["report"]["stats"]["by_severity"]["high"] > 0
    assert set(data["files"]) == {"pqc-report.json", "pqc-report.sarif", "cbom.cdx.json", "pqc-report.md"}


def test_scan_zip(srv):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    code, body = req(srv + "/api/scan/zip", data=buf.getvalue(), method="POST",
                     headers={"X-Pqcscan-Token": "t0k3n", "X-Pqcscan-Filename": "my.zip"})
    data = json.loads(body)
    assert code == 200 and data["report"]["target"] == "my.zip"
    assert [f["rule_id"] for f in data["report"]["findings"]] == ["py.rsa-keygen"]


def test_missing_path_gives_clear_error(srv):
    code, body = req(srv + "/api/scan/path", data=b'{"path": "/no/such/dir"}', method="POST",
                     headers={"X-Pqcscan-Token": "t0k3n"})
    assert code == 400 and "not found" in json.loads(body)["error"]


def test_rules_endpoint(srv):
    code, body = req(srv + "/api/rules")
    assert code == 200 and len(json.loads(body)["rules"]) >= 60
