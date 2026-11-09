import io
import json
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from pqcscan import report
from pqcscan.cli import main
from pqcscan.models import Kind, Severity
from pqcscan.plan import build_plan
from pqcscan.scanner import ScanOptions, scan_bytes_zip, scan_path, scan_text

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"


def ids(findings):
    return {f.rule_id for f in findings}


# Rules, one language at a time

@pytest.mark.parametrize("lang,code,expected", [
    ("python", "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "py.rsa-keygen"),
    ("python", "ct = pub.encrypt(m, padding.OAEP(mgf=x, algorithm=y, label=None))", "py.rsa-encrypt"),
    ("python", "shared = priv.exchange(ec.ECDH(), peer)", "py.ecdh"),
    ("python", "k = X25519PrivateKey.generate()", "py.x25519"),
    ("python", "h = hashlib.md5(b'x')", "py.weak-hash"),
    ("javascript", "const k = generateKeyPairSync(\n  'rsa',\n  { modulusLength: 2048 })", "js.rsa-keygen"),
    ("javascript", "const k = crypto.generateKeyPairSync('ed25519')", "js.ed25519"),
    ("javascript", "await crypto.subtle.generateKey({ name: 'RSA-OAEP' }, true, [])", "js.webcrypto-kex"),
    ("javascript", "createCipheriv('des-ede3-cbc', k, iv)", "js.weak-cipher"),
    ("go", "k, _ := rsa.GenerateKey(rand.Reader, 2048)", "go.rsa-keygen"),
    ("go", "c := ecdh.X25519()", "go.ecdh"),
    ("go", "cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}", "go.tls-curves"),
    ("go", "cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}", "any.pqc-hybrid-tls"),
    ("java", 'KeyAgreement ka = KeyAgreement.getInstance("ECDH");', "java.keyagreement"),
    ("java", 'Cipher c = Cipher.getInstance("AES");', "java.weak-cipher"),
    ("java", 'Signature s = Signature.getInstance("SHA256withRSA");', "java.signature"),
    ("csharp", "using var rsa = RSA.Create(2048);", "cs.rsa"),
    ("c", "RSA *r = RSA_generate_key(2048, RSA_F4, NULL, NULL);", "c.rsa"),
    ("rust", "let key = RsaPrivateKey::new(&mut rng, 2048)?;", "rs.rsa"),
    ("config", "ssl_protocols TLSv1 TLSv1.2;", "cfg.weak-tls"),
    ("python", 'kem = oqs.KeyEncapsulation("ML-KEM-768")', "any.pqc"),
    ("javascript", 'jwt.sign(payload, key, { algorithm: "ES256" })', "any.jwt-asym"),
])
def test_rule_matches(lang, code, expected):
    assert expected in ids(scan_text("f", code, lang, False))


@pytest.mark.parametrize("lang,code,unexpected", [
    ("config", "ssl_protocols TLSv1.2 TLSv1.3;", "cfg.weak-tls"),
    ("go", "cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}", "go.tls-curves"),
    ("python", "h = hashlib.sha256(b'x')", "py.weak-hash"),
    ("java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");', "java.weak-cipher"),
    ("python", "rsa_key_path = settings.RSA_KEY", "py.rsa-keygen"),
])
def test_no_false_positive(lang, code, unexpected):
    assert unexpected not in ids(scan_text("f", code, lang, False))


def test_suppression_comment():
    code = "h = hashlib.md5(b'x')  # pqcscan:ignore non-security cache key"
    assert scan_text("f.py", code, "python", False) == []


def test_comment_lowers_confidence():
    [f] = scan_text("f.py", "# rsa.generate_private_key(...) was removed", "python", False)
    assert f.confidence == "low"


def test_import_line_dropped_when_used():
    code = ("from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey\n"
            "k = X25519PrivateKey.generate()\n")
    found = scan_text("f.py", code, "python", False)
    assert [f.line for f in found] == [2]


def test_multiline_match_reports_start_line():
    code = "x = 1\nconst k = generateKeyPairSync(\n  'rsa', {})\n"
    [f] = scan_text("a.ts", code, "javascript", False)
    assert f.line == 2


# Whole-project scan

@pytest.fixture(scope="module")
def example_result():
    return scan_path(EXAMPLE)


def test_example_covers_all_categories(example_result):
    kinds = {f.kind for f in example_result.findings}
    assert {Kind.QUANTUM_KEX, Kind.QUANTUM_SIG, Kind.QUANTUM_KEY, Kind.CLASSICAL_WEAK,
            Kind.SECRET, Kind.PQC, Kind.INVENTORY} <= kinds


def test_example_key_files(example_result):
    by_rule = {}
    for f in example_result.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    [cert] = by_rule["key.certificate"]
    assert cert.algorithm == "RSA-2048"
    assert cert.severity == Severity.HIGH          # valid past 2035
    ssh = {f.algorithm: f for f in by_rule["key.ssh-public-key"]}
    assert ssh["ssh-rsa"].severity == Severity.HIGH   # 1024-bit
    assert ssh["ssh-ed25519"].severity == Severity.MEDIUM


def test_test_files_are_tagged_and_can_be_skipped(example_result):
    assert any(f.context == "test" for f in example_result.findings)
    no_tests = scan_path(EXAMPLE, ScanOptions(include_tests=False))
    assert not any(f.context == "test" for f in no_tests.findings)


def test_dependencies(example_result):
    deps = {f.algorithm: f.kind for f in example_result.findings if f.rule_id.startswith("dep.")}
    assert deps["cryptography"] == Kind.INVENTORY
    assert deps["liboqs-python"] == Kind.PQC
    assert "node-forge" in deps and "golang.org/x/crypto" in deps


def test_zip_scan_matches_directory(example_result):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in EXAMPLE.rglob("*"):
            if p.is_file():
                zf.write(p, p.relative_to(EXAMPLE).as_posix())
    zres = scan_bytes_zip(buf.getvalue())
    key = lambda r: sorted((f.rule_id, f.location, f.line) for f in r.findings)
    assert key(zres) == key(example_result)


def test_zip_path_traversal_is_ignored():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.py", "rsa.generate_private_key(1, 2)")
        zf.writestr("ok.py", "rsa.generate_private_key(1, 2)")
    res = scan_bytes_zip(buf.getvalue())
    assert {f.location for f in res.findings} == {"ok.py"}


def test_plan_waves(example_result):
    waves = {w.key: w for w in build_plan(example_result)}
    assert list(waves) == ["fix-now", "wave-1", "wave-2", "verify"]
    wave1 = {i.title for i in waves["wave-1"].items}
    assert "RSA: key exchange / encryption" in wave1
    assert all(i.kind != Kind.QUANTUM_SIG for i in waves["wave-1"].items)


# Output formats

def test_sarif_structure(example_result):
    sarif = json.loads(report.to_sarif(example_result))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note")
        region = res["locations"][0]["physicalLocation"].get("region")
        if region:
            assert region["startLine"] >= 1


CDX_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
                  "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}
CDX_FUNCTIONS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
                 "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"}


def test_cbom_structure(example_result):
    bom = json.loads(report.to_cbom(example_result))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    assert set(bom["dependencies"][0]["dependsOn"]) == set(refs)
    asset_types = set()
    for c in bom["components"]:
        assert c["type"] in ("cryptographic-asset", "library")
        assert c["evidence"]["occurrences"]
        if c["type"] == "cryptographic-asset":
            cp = c["cryptoProperties"]
            asset_types.add(cp["assetType"])
            if cp["assetType"] == "algorithm":
                ap = cp["algorithmProperties"]
                assert ap["primitive"] in CDX_PRIMITIVES
                assert set(ap["cryptoFunctions"]) <= CDX_FUNCTIONS
                assert ap.get("nistQuantumSecurityLevel", 0) in range(0, 7)
    assert {"algorithm", "certificate", "related-crypto-material"} <= asset_types


def test_markdown_and_json(example_result):
    md = report.to_markdown(example_result)
    assert "## Migration plan" in md and "NIST IR 8547" in md
    doc = json.loads(report.to_json(example_result))
    assert doc["stats"]["files_scanned"] == example_result.files_scanned
    assert len(doc["findings"]) == len(example_result.findings)


def test_private_key_snippet_is_not_leaked(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    (tmp_path / "server.key").write_bytes(pem)
    (tmp_path / "conf.py").write_text('KEY = """' + pem.decode() + '"""\n')
    res = scan_path(tmp_path)
    secrets = [f for f in res.findings if f.kind == Kind.SECRET]
    assert {f.location for f in secrets} == {"server.key", "conf.py"}
    body = pem.decode().splitlines()[1]
    dumped = report.to_json(res) + report.to_sarif(res) + report.to_cbom(res)
    assert body not in dumped
    assert next(f for f in secrets if f.location == "server.key").algorithm == "ECDSA-secp256r1"


# CLI

def test_cli_fail_on_and_out_dir(tmp_path):
    runner = CliRunner()
    res = runner.invoke(main, ["scan", str(EXAMPLE), "--out-dir", str(tmp_path), "--fail-on", "high"])
    assert res.exit_code == 1, res.output
    assert {p.name for p in tmp_path.iterdir()} == {
        "pqc-report.json", "pqc-report.sarif", "cbom.cdx.json", "pqc-report.md"}


def test_cli_clean_project_passes(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nprint(hashlib.sha256(b'x').hexdigest())\n")
    res = CliRunner().invoke(main, ["scan", str(tmp_path), "--fail-on", "medium"])
    assert res.exit_code == 0, res.output


def test_cli_rules_lists_everything():
    res = CliRunner().invoke(main, ["rules"])
    assert res.exit_code == 0 and "py.rsa-keygen" in res.output


def test_ca_bundle_is_summarised(tmp_path):
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    pems = []
    for i in range(12):
        k = ec.generate_private_key(ec.SECP256R1())
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Root {i}")])
        now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
             .serial_number(i + 1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
             .sign(k, hashes.SHA256()))
        pems.append(c.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "cacert.pem").write_bytes(b"".join(pems))
    res = scan_path(tmp_path)
    [f] = res.findings
    assert f.rule_id == "key.trust-bundle" and "12 ECDSA-secp256r1" in f.detail
    assert json.loads(report.to_cbom(res))["components"] == []
