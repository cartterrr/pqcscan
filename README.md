# pqcscan

A small scanner that looks for quantum-vulnerable crypto (RSA, ECDSA, ECDH,
X25519, Ed25519, DH, DSA) in a codebase and on TLS servers, and turns what it
finds into a rough migration plan.

It reads source code, config files, keys and certificates, and dependency
manifests. Output is a terminal summary, plus JSON, Markdown, SARIF (for GitHub
code scanning) and a CycloneDX 1.6 CBOM if you want them. Everything runs
locally; nothing is uploaded anywhere.

Русская версия: [README.ru.md](README.ru.md).

```
$ pqcscan scan examples/vulnerable-app
app/crypto_utils.py
     11  HIGH   RSA key generation (RSA)
     17  HIGH   RSA encryption (OAEP / PKCS#1 v1.5) (RSA-OAEP)
     22  MEDIUM ECDSA signature (ECDSA)
     26  HIGH   X25519 / X448 key agreement (X25519)
     31  MEDIUM MD5 / SHA-1 hash (MD5/SHA-1)
...
Summary: 14 high, 13 medium, 0 low, 9 info

Migration plan
  Fix now (classical problems): 7 occurrences (immediately)
  Wave 1: key exchange and encryption: 11 occurrences (start now, done by 2030)
  Wave 2: signatures and authentication: 9 occurrences (plan now, done by 2035)
  Verify existing post-quantum usage: 4 occurrences (next review)
```

The full report for that demo project is in
[docs/sample-report/pqc-report.md](docs/sample-report/pqc-report.md).

## Background

Shor's algorithm on a big enough quantum computer breaks RSA and elliptic-curve
crypto. Nobody has that machine yet, but traffic recorded today can be decrypted
once someone does, so anything that does key exchange is already worth looking
at. Signatures are less urgent: forging one needs the quantum computer at the
time of the attack.

NIST finished the replacement standards in 2024: ML-KEM (FIPS 203) for key
exchange, ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) for signatures. The dates
people are planning around:

| Source | When | What |
|---|---|---|
| NIST IR 8547 (final, Oct 2026) | after 2030 | RSA, ECDSA, EdDSA, (EC)DH deprecated, any key size |
| NIST IR 8547 | after 2035 | disallowed |
| UK NCSC | 2028 / 2031 / 2035 | inventory / high-priority systems / everything |
| EU coordinated roadmap | end of 2026 / 2030 / 2035 | first steps / high-risk systems / done |

All of these plans start with an inventory, which is the part this tool helps with.

## Install

```bash
git clone https://github.com/cartterrr/pqcscan
cd pqcscan
pip install -e .
```

Python 3.10 or newer. The only dependencies are `click` and `cryptography`.

## Web interface

```bash
pqcscan ui
```

This opens a page in your browser where you can drop a .zip, point it at a
folder, check TLS servers, browse the findings and the migration plan, and
download the reports. It's the same engine as the command line.

The server listens on 127.0.0.1 only, and every scan request has to carry a
random token that's built into the page, so other websites can't use it. The
title font (Cinzel Decorative) comes from Google Fonts; offline, the page falls
back to a system serif and everything else works the same. Use `--port` to pick
another port and `--no-browser` to skip opening a tab.

## Usage

```bash
pqcscan scan path/to/repo                 # directory, single file or .zip
pqcscan scan project.zip --no-tests -x "docs/*"
pqcscan scan . --out-dir pqc-reports      # writes JSON, SARIF, CBOM and Markdown
pqcscan scan . -f cbom -o cbom.cdx.json   # or one format at a time
pqcscan scan . --fail-on high             # exit code 1 if there are high findings
pqcscan tls example.com api.example.com:8443
pqcscan rules
```

`--fail-on` ignores matches in test files and in comments, so a CI job doesn't
fail because a test generates an RSA key.

If you've reviewed a line and want it gone from the report, put
`pqcscan:ignore` in a comment on that line.

Only point `pqcscan tls` at servers you own or have permission to test.

## What gets checked

Source code in Python, JS/TS, Go, Java/Kotlin, C#, C/C++ and Rust. There are 70
regex rules, each tied to a specific library call: `rsa.generate_private_key`,
`generateKeyPairSync('rsa')`, `ecdsa.GenerateKey`,
`KeyAgreement.getInstance("ECDH")`, WebCrypto, OpenSSL and so on. Calls split
across several lines still match. Run `pqcscan rules` for the full list.

Config files: TLS 1.0/1.1 and weak ciphers in nginx/Apache-style configs, RSA
and DSA host keys in SSH configs.

Keys and certificates (`.pem`, `.crt`, `.key`, `.pub`, `authorized_keys`): the
scanner parses them and reports algorithm, key size and expiry. A certificate
that is still valid after 2035 gets bumped to high. Private keys are reported
but their contents never end up in any output. Big CA bundles like certifi's
`cacert.pem` get one summary line instead of a hundred-odd findings.

Dependencies (`requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`,
`pom.xml`, `Cargo.toml` and a few others): which crypto libraries are pulled
in, including post-quantum ones like liboqs, CIRCL, `@noble/post-quantum` and
Bouncy Castle PQC.

It also notices post-quantum code that is already there (ML-KEM, ML-DSA,
SLH-DSA, `X25519MLKEM768`, old Kyber/Dilithium names). Those are reported as
info, because finding ML-KEM in the code doesn't tell you it's used correctly.

### The TLS check

For each server, `pqcscan tls` does a normal handshake to get the protocol
version, cipher and certificate, and tries TLS 1.0/1.1 to see if they're still
accepted.

The interesting bit is checking for hybrid post-quantum key exchange. Python's
`ssl` module can't tell you which key exchange group was negotiated, so the
scanner builds a TLS 1.3 ClientHello by hand. It lists only the hybrid groups
(`X25519MLKEM768` is `0x11EC`, plus `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`
and the old `X25519Kyber768Draft00`) and sends no key share. A server that
supports one of them answers with a HelloRetryRequest that names the group. A
server that doesn't answers with a `handshake_failure` alert. The client never
has to do any ML-KEM math, so this works with any Python and OpenSSL. The code
is in [src/pqcscan/tls.py](src/pqcscan/tls.py).

### Severities

| What | Severity | Reason |
|---|---|---|
| RSA encryption, ECDH, X25519, DH, TLS without a hybrid group | high | exposed to record-now-decrypt-later |
| Key generation where the use isn't clear | high | could be an encryption key, someone has to check |
| RSA/ECDSA/EdDSA signatures, JWT RS256/ES256, SSH keys | medium | only matters once a quantum computer exists |
| Certificate valid after 2035 | high | outlives the NIST cutoff |
| MD5, SHA-1, DES, RC4, ECB, TLS 1.0/1.1 | medium | broken already, quantum or not |
| Private key committed to the repo | high | rotate it |
| PQC code, crypto dependencies | info | for the inventory |

## Output files

`--out-dir` writes four files:

- `pqc-report.md` is the one to read: summary, migration plan with file
  locations and advice, the deadlines table, and every finding.
- `cbom.cdx.json` is a CycloneDX 1.6 CBOM. Algorithms, certificates, keys and
  TLS endpoints are `cryptographic-asset` components with
  `evidence.occurrences` (file and line) and `nistQuantumSecurityLevel`.
  Libraries are plain `library` components. The CI job checks the file against
  the official schema.
- `pqc-report.sarif` is SARIF 2.1.0 with `security-severity` set, so GitHub
  shows findings under Security > Code scanning.
- `pqc-report.json` has all of the above for scripts.

## GitHub Actions

```yaml
- run: pip install git+https://github.com/cartterrr/pqcscan
- run: pqcscan scan . --out-dir pqc-reports --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: pqc-reports/pqc-report.sarif
```

## Limitations

The rules match API calls; they don't follow data flow. Each finding needs a
person to check how the key is actually used, and a clean report doesn't mean
the system is quantum-safe. The scanner doesn't look at compiled binaries,
container images, HSMs, cloud KMS settings, third-party services, or crypto
that is picked at runtime from config. The TLS check only sees what a server
offers to this particular client on one host and port.

## Ideas for later

- [ ] Python AST mode, to tell encryption keys from signing keys
- [ ] SSH server check (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`)
- [ ] Scanning JARs and Go binaries for imported crypto symbols
- [ ] Baseline file, so pull requests only show new findings
- [ ] HTML report

## References

- NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM),
  [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA),
  [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA)
- NIST IR 8547, final version, October 2026
  ([CSA summary](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ir8547-pqc-transition-20261030-csa-st/))
- UK NCSC and EU timelines, summarised by
  [PQShield](https://pqshield.com/pqc-transition-roadmaps-and-guidance/)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)
- IETF draft-ietf-tls-ecdhe-mlkem (the hybrid ML-KEM groups for TLS 1.3)
- [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (TLS 1.0 and 1.1 deprecation)

## License

MIT
