# Changelog

## v0.1.0

First release.

- `pqcscan scan` looks through a folder or a .zip for RSA, ECDSA, ECDH,
  X25519, Ed25519, DH and DSA usage in Python, JS/TS, Go, Java/Kotlin, C#,
  C/C++ and Rust (70 rules), plus weak TLS settings in config files.
- Key and certificate files are parsed: algorithm, key size, expiry. A
  certificate that is still valid after 2035 is flagged as high. Private keys
  are reported but never printed.
- Dependency files (`requirements.txt`, `package.json`, `go.mod`, `pom.xml`,
  `Cargo.toml` and others) are checked for crypto and post-quantum libraries.
- `pqcscan tls` checks live servers, including whether they accept hybrid
  post-quantum key exchange (`X25519MLKEM768`), using a hand-built TLS 1.3
  ClientHello.
- Findings are grouped into a migration plan: fix now, key exchange first,
  signatures second, then checking existing post-quantum code.
- Reports: terminal, Markdown, JSON, SARIF 2.1.0 and a CycloneDX 1.6 CBOM.
- `pqcscan ui` opens a local web interface on 127.0.0.1.

Install:

```bash
pip install https://github.com/cartterrr/pqcscan/releases/download/v0.1.0/pqcscan-0.1.0-py3-none-any.whl
```
