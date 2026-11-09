"""Detection rules for source code and config files.

Each rule is a regex for one library call, tagged with the algorithm and what
it's used for (key exchange, signing, hashing...). That tag decides the
severity, the CBOM entry and which migration wave the finding lands in.

Patterns run over the whole file rather than line by line, so a call split
across lines still matches. The line we report is where the match starts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Kind, Severity

# Languages

LANGUAGES: dict[str, tuple[str, ...]] = {
    "python": (".py", ".pyi"),
    "javascript": (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"),
    "go": (".go",),
    "java": (".java", ".kt", ".kts", ".scala", ".groovy"),
    "c": (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"),
    "rust": (".rs",),
    "csharp": (".cs",),
    "config": (".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg",
               ".properties", ".xml", ".env", ".tf", ".hcl"),
}
SPECIAL_FILENAMES = {"nginx.conf": "config", "httpd.conf": "config", "sshd_config": "config",
                     "ssh_config": "config", "openssl.cnf": "config", "dockerfile": "config"}
CODE_LANGS = frozenset({"python", "javascript", "go", "java", "c", "rust", "csharp"})
ALL_LANGS = CODE_LANGS | {"config"}


def language_for(filename: str) -> str | None:
    name = filename.rsplit("/", 1)[-1].lower()
    if name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[name]
    for lang, exts in LANGUAGES.items():
        if name.endswith(exts):
            return lang
    return None


# Remediation advice, keyed by usage

REMEDIATION = {
    "kex": (
        "Anything encrypted this way can be recorded now and decrypted later, once a "
        "quantum computer exists. Switch key exchange to a hybrid of X25519 and "
        "ML-KEM-768 (FIPS 203). In TLS that means enabling the X25519MLKEM768 group, "
        "which OpenSSL 3.5+ and Go 1.24+ support. If the app wraps data keys with "
        "RSA-OAEP or ECDH itself, use a hybrid KEM there instead."
    ),
    "sig": (
        "A quantum computer could forge these signatures, but it can't go back and "
        "break old ones, so this can usually wait until key exchange is done. The "
        "replacement is ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) for long-lived "
        "roots and firmware signing. Reading the algorithm from config makes the "
        "switch much easier later."
    ),
    "key": (
        "It isn't clear from this line whether the key encrypts or signs. If it "
        "encrypts or does key exchange, treat it as urgent (hybrid ML-KEM); if it "
        "signs, it can wait for ML-DSA. Also note where the key is stored and how "
        "long the data it protects needs to stay secret."
    ),
    "weak": (
        "This is broken or deprecated even without a quantum computer, so fix it now: "
        "SHA-256 or better instead of MD5/SHA-1, AES-GCM or ChaCha20-Poly1305 instead "
        "of DES/3DES/RC4/ECB, and TLS 1.2 at minimum (1.3 if you can)."
    ),
    "secret": (
        "A private key is checked into the repo. Rotate it, scrub it from git "
        "history, and load keys from a secret manager or HSM from now on."
    ),
    "pqc": (
        "Post-quantum crypto is already here, which is good, but check it: the "
        "parameter set (ML-KEM-768, ML-DSA-65 and so on), that it uses the final FIPS "
        "versions and not the old Kyber/Dilithium drafts, and that it runs in hybrid "
        "mode where that's expected."
    ),
    "jwt": (
        "The JWT is signed with RSA, ECDSA or EdDSA. Tokens are short-lived, so this "
        "is not urgent, but whatever issues them should be able to change algorithm "
        "without a redeploy. IETF is working on ML-DSA for JOSE/COSE."
    ),
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    algorithm: str
    primitive: str
    kind: Kind
    severity: Severity
    langs: frozenset
    pattern: re.Pattern
    remediation: str
    quantum_level: int | None = 0


RULES: list[Rule] = []


def _r(rule_id, title, algorithm, primitive, kind, severity, langs, pattern,
       remediation=None, flags=0, quantum_level=0):
    if isinstance(langs, str):
        langs = {langs}
    rem = remediation or {
        Kind.QUANTUM_KEX: "kex", Kind.QUANTUM_SIG: "sig", Kind.QUANTUM_KEY: "key",
        Kind.CLASSICAL_WEAK: "weak", Kind.SECRET: "secret", Kind.PQC: "pqc",
    }.get(kind, "key")
    RULES.append(Rule(rule_id, title, algorithm, primitive, kind, severity,
                      frozenset(langs), re.compile(pattern, flags), REMEDIATION[rem],
                      quantum_level))


K, S, KEY, W, SEC, P = (Kind.QUANTUM_KEX, Kind.QUANTUM_SIG, Kind.QUANTUM_KEY,
                        Kind.CLASSICAL_WEAK, Kind.SECRET, Kind.PQC)
H, M, L, I = Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO

# Python
_r("py.rsa-keygen", "RSA key generation", "RSA", "pke", KEY, H, "python",
   r"\brsa\.generate_private_key\s*\(|\bRSA\.generate\s*\(|\brsa\.newkeys\s*\(")
_r("py.rsa-encrypt", "RSA encryption (OAEP / PKCS#1 v1.5)", "RSA-OAEP", "pke", K, H, "python",
   r"\bpadding\.OAEP\s*\(|\bPKCS1_OAEP\.new\s*\(|\bPKCS1_v1_5\.new\s*\(|\brsa\.encrypt\s*\(")
_r("py.rsa-sign", "RSA signature", "RSA-PSS/PKCS1", "signature", S, M, "python",
   r"\bpadding\.PSS\s*\(|\bpss\.new\s*\(|\bpkcs1_15\.new\s*\(|\brsa\.sign\s*\(")
_r("py.ec-keygen", "Elliptic-curve key generation", "ECC", "pke", KEY, H, "python",
   r"\bec\.generate_private_key\s*\(|\bECC\.generate\s*\(|\bSigningKey\.generate\s*\(")
_r("py.ecdh", "ECDH key agreement", "ECDH", "key-agree", K, H, "python",
   r"\bec\.ECDH\s*\(\s*\)")
_r("py.ecdsa", "ECDSA signature", "ECDSA", "signature", S, M, "python",
   r"\bec\.ECDSA\s*\(|\bDSS\.new\s*\(")
_r("py.x25519", "X25519 / X448 key agreement", "X25519", "key-agree", K, H, "python",
   r"\bX(?:25519|448)PrivateKey\b|\bnacl\.public\.(?:PrivateKey|Box)\b|\bfrom\s+nacl\.public\s+import\b")
_r("py.ed25519", "Ed25519 / Ed448 signature", "Ed25519", "signature", S, M, "python",
   r"\bEd(?:25519|448)PrivateKey\b|\bnacl\.signing\.SigningKey\b|\bfrom\s+nacl\.signing\s+import\b")
_r("py.dh", "Finite-field Diffie-Hellman", "DH", "key-agree", K, H, "python",
   r"\bdh\.generate_parameters\s*\(|\bDHParameterNumbers\s*\(")
_r("py.dsa", "DSA signature", "DSA", "signature", S, M, "python",
   r"\bdsa\.generate_private_key\s*\(|\bDSA\.generate\s*\(")
_r("py.ssh-keys", "Paramiko RSA/ECDSA/Ed25519 key", "SSH-RSA/ECDSA/Ed25519", "signature", S, M,
   "python", r"\b(?:paramiko\.)?(?:RSAKey|ECDSAKey|Ed25519Key|DSSKey)\s*(?:\.\w+)?\s*\(")
_r("py.weak-hash", "MD5 / SHA-1 hash", "MD5/SHA-1", "hash", W, M, "python",
   r"\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*['\"](?:md5|sha1)['\"]|\b(?:MD5|SHA1)\.new\s*\(|\bhashes\.(?:MD5|SHA1)\s*\(")
_r("py.weak-cipher", "DES / 3DES / RC4 / Blowfish / ECB", "DES/3DES/RC4/ECB", "block-cipher", W, M,
   "python", r"\b(?:DES3?|ARC4|Blowfish)\.new\s*\(|\balgorithms\.(?:TripleDES|ARC4|Blowfish)\s*\(|\bmodes\.ECB\s*\(|\bMODE_ECB\b")
_r("py.weak-tls", "TLS 1.0 / 1.1 allowed", "TLS1.0/1.1", "other", W, M, "python",
   r"\bssl\.PROTOCOL_TLSv1(?:_1)?\b|\bTLSVersion\.TLSv1(?:_1)?\b|\bPROTOCOL_SSLv[23]\b")

# JavaScript / TS
_GKP = r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"`]"
_r("js.rsa-keygen", "RSA key generation (node:crypto)", "RSA", "pke", KEY, H, "javascript",
   _GKP + r"rsa(?:-pss)?['\"`]|\bforge\.pki\.rsa\.generateKeyPair\b|\bnew\s+NodeRSA\s*\(")
_r("js.ec-keygen", "EC key generation (node:crypto)", "ECC", "pke", KEY, H, "javascript",
   _GKP + r"ec['\"`]")
_r("js.x25519", "X25519 / X448 key agreement", "X25519", "key-agree", K, H, "javascript",
   _GKP + r"x(?:25519|448)['\"`]|\bnacl\.box\b|\bx25519\.getSharedSecret\s*\(")
_r("js.ed25519", "Ed25519 / Ed448 signature", "Ed25519", "signature", S, M, "javascript",
   _GKP + r"ed(?:25519|448)['\"`]|\bnacl\.sign\b|\bed25519\.sign\s*\(")
_r("js.dsa-dh-keygen", "DSA / DH key generation", "DSA/DH", "pke", KEY, H, "javascript",
   _GKP + r"(?:dsa|dh)['\"`]")
_r("js.rsa-encrypt", "RSA public-key encryption", "RSA", "pke", K, H, "javascript",
   r"\bcrypto\.(?:publicEncrypt|privateDecrypt)\s*\(|\b(?:publicEncrypt|privateDecrypt)\s*\(")
_r("js.ecdh", "ECDH / Diffie-Hellman", "ECDH/DH", "key-agree", K, H, "javascript",
   r"\bcreateECDH\s*\(|\bcreateDiffieHellman(?:Group)?\s*\(|\bgetDiffieHellman\s*\(|\bdiffieHellman\s*\(\s*\{")
_r("js.sign", "Asymmetric sign/verify (node:crypto)", "RSA/ECDSA", "signature", S, M, "javascript",
   r"\bcrypto\.(?:createSign|createVerify)\s*\(|\bcrypto\.sign\s*\(\s*['\"`]?[\w-]*['\"`]?\s*,")
_r("js.webcrypto-kex", "WebCrypto RSA-OAEP / ECDH / X25519", "RSA-OAEP/ECDH", "key-agree", K, H,
   "javascript", r"name\s*:\s*['\"`](?:RSA-OAEP|ECDH|X25519)['\"`]")
_r("js.webcrypto-sig", "WebCrypto RSA / ECDSA / Ed25519 signature", "RSASSA/ECDSA/Ed25519",
   "signature", S, M, "javascript",
   r"name\s*:\s*['\"`](?:RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|Ed25519)['\"`]")
_r("js.elliptic", "elliptic / secp256k1 curve", "ECDSA", "signature", S, M, "javascript",
   r"\bnew\s+(?:EC|elliptic\.ec)\s*\(\s*['\"`](?:secp256k1|p256|p384|curve25519|ed25519)['\"`]|\bsecp256k1\.sign\s*\(")
_r("js.weak-hash", "MD5 / SHA-1 hash", "MD5/SHA-1", "hash", W, M, "javascript",
   r"\bcreateHash\s*\(\s*['\"`](?:md5|sha1)['\"`]|\bCryptoJS\.(?:MD5|SHA1)\s*\(|\bmd5\s*\(")
_r("js.weak-cipher", "DES / 3DES / RC4 / ECB", "DES/3DES/RC4/ECB", "block-cipher", W, M, "javascript",
   r"\bcreateCipheriv\s*\(\s*['\"`](?:des|des-ede3|rc4|bf|aes-\d+-ecb)[\w-]*['\"`]|\bCryptoJS\.(?:DES|TripleDES|RC4)\b|\bCryptoJS\.mode\.ECB\b")
_r("js.weak-tls", "TLS 1.0 / 1.1 allowed", "TLS1.0/1.1", "other", W, M, "javascript",
   r"minVersion\s*:\s*['\"`]TLSv1(?:\.1)?['\"`]|secureProtocol\s*:\s*['\"`]TLSv1(?:_1)?_method['\"`]")

# Go
_r("go.rsa-keygen", "RSA key generation", "RSA", "pke", KEY, H, "go", r"\brsa\.GenerateKey\s*\(")
_r("go.rsa-encrypt", "RSA encryption", "RSA-OAEP", "pke", K, H, "go",
   r"\brsa\.(?:EncryptOAEP|EncryptPKCS1v15|DecryptOAEP|DecryptPKCS1v15)\s*\(")
_r("go.rsa-sign", "RSA signature", "RSA-PSS/PKCS1", "signature", S, M, "go",
   r"\brsa\.(?:SignPSS|SignPKCS1v15|VerifyPSS|VerifyPKCS1v15)\s*\(")
_r("go.ecdsa", "ECDSA key / signature", "ECDSA", "signature", S, M, "go",
   r"\becdsa\.(?:GenerateKey|Sign|SignASN1|Verify|VerifyASN1)\s*\(")
_r("go.ecdh", "ECDH / X25519 key agreement", "ECDH", "key-agree", K, H, "go",
   r"\becdh\.(?:P256|P384|P521|X25519)\s*\(\s*\)|\bcurve25519\.(?:X25519|ScalarMult)\s*\(|\bbox\.(?:Seal|Open|GenerateKey)\s*\(")
_r("go.ed25519", "Ed25519 signature", "Ed25519", "signature", S, M, "go",
   r"\bed25519\.(?:GenerateKey|Sign|Verify|NewKeyFromSeed)\s*\(")
_r("go.dsa", "DSA", "DSA", "signature", S, M, "go", r"\bdsa\.(?:GenerateKey|GenerateParameters|Sign)\s*\(")
_r("go.tls-curves", "TLS configured with classical-only curves", "ECDHE", "key-agree", K, H, "go",
   r"CurvePreferences\s*:\s*\[\]tls\.CurveID\s*\{(?![^}]*MLKEM)[^}]*\}")
_r("go.weak-hash", "MD5 / SHA-1 hash", "MD5/SHA-1", "hash", W, M, "go",
   r"\b(?:md5|sha1)\.(?:New|Sum)\s*\(")
_r("go.weak-cipher", "DES / 3DES / RC4", "DES/RC4", "block-cipher", W, M, "go",
   r"\bdes\.(?:NewCipher|NewTripleDESCipher)\s*\(|\brc4\.NewCipher\s*\(")
_r("go.weak-tls", "TLS 1.0 / 1.1 allowed", "TLS1.0/1.1", "other", W, M, "go",
   r"\btls\.VersionTLS1[01]\b|\btls\.VersionSSL30\b")
_r("go.insecure-skip", "TLS certificate verification disabled", "TLS", "other", W, M, "go",
   r"InsecureSkipVerify\s*:\s*true")

# Java
_r("java.rsa-keygen", "RSA key generation", "RSA", "pke", KEY, H, "java",
   r"KeyPairGenerator\.getInstance\s*\(\s*\"RSA(?:SSA-PSS)?\"")
_r("java.ec-keygen", "EC key generation", "ECC", "pke", KEY, H, "java",
   r"KeyPairGenerator\.getInstance\s*\(\s*\"EC\"")
_r("java.dh-keygen", "DH / XDH key generation", "DH/XDH", "key-agree", K, H, "java",
   r"KeyPairGenerator\.getInstance\s*\(\s*\"(?:DH|DiffieHellman|XDH|X25519|X448)\"")
_r("java.ed-keygen", "EdDSA / DSA key generation", "EdDSA/DSA", "signature", S, M, "java",
   r"KeyPairGenerator\.getInstance\s*\(\s*\"(?:Ed25519|Ed448|EdDSA|DSA)\"")
_r("java.rsa-cipher", "RSA encryption (javax.crypto.Cipher)", "RSA", "pke", K, H, "java",
   r"Cipher\.getInstance\s*\(\s*\"RSA")
_r("java.keyagreement", "ECDH / DH / XDH key agreement", "ECDH/DH", "key-agree", K, H, "java",
   r"KeyAgreement\.getInstance\s*\(\s*\"(?:ECDH|DH|DiffieHellman|XDH|X25519|X448)\"")
_r("java.signature", "RSA / ECDSA / EdDSA / DSA signature", "RSA/ECDSA/EdDSA", "signature", S, M,
   "java", r"Signature\.getInstance\s*\(\s*\"(?:\w*with(?:RSA|ECDSA|DSA|RSA/PSS)\w*|Ed25519|Ed448|EdDSA|RSASSA-PSS)\"")
_r("java.weak-hash", "MD5 / SHA-1 hash", "MD5/SHA-1", "hash", W, M, "java",
   r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-?1)\"")
_r("java.weak-cipher", "DES / 3DES / RC4 / ECB", "DES/RC4/ECB", "block-cipher", W, M, "java",
   r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|RC4|ARCFOUR|Blowfish|AES/ECB|AES\")")
_r("java.weak-tls", "TLS 1.0 / 1.1 allowed", "TLS1.0/1.1", "other", W, M, "java",
   r"SSLContext\.getInstance\s*\(\s*\"(?:SSL|SSLv3|TLSv1|TLSv1\.1)\"")

# C#
_r("cs.rsa", "RSA key / encryption", "RSA", "pke", KEY, H, "csharp",
   r"\bRSA\.Create\s*\(|\bnew\s+RSACryptoServiceProvider\s*\(|\bRSACng\b")
_r("cs.ecdh", "ECDiffieHellman", "ECDH", "key-agree", K, H, "csharp",
   r"\bECDiffieHellman(?:Cng)?\.Create\s*\(|\bnew\s+ECDiffieHellmanCng\s*\(")
_r("cs.ecdsa", "ECDsa / DSA signature", "ECDSA", "signature", S, M, "csharp",
   r"\bECDsa(?:Cng)?\.Create\s*\(|\bDSA\.Create\s*\(")
_r("cs.weak", "MD5 / SHA-1 / DES / 3DES", "MD5/SHA-1/DES", "hash", W, M, "csharp",
   r"\b(?:MD5|SHA1|DES|TripleDES|RC2)\.Create\s*\(|\bnew\s+(?:MD5|SHA1)CryptoServiceProvider\s*\(")

# C/C++
_r("c.rsa", "OpenSSL RSA", "RSA", "pke", KEY, H, "c",
   r"\bRSA_generate_key(?:_ex)?\s*\(|\bRSA_(?:public|private)_(?:encrypt|decrypt)\s*\(|\bEVP_PKEY_RSA\b|\bEVP_RSA_gen\s*\(")
_r("c.ec", "OpenSSL EC key / ECDSA", "ECDSA", "signature", S, M, "c",
   r"\bEC_KEY_new_by_curve_name\s*\(|\bECDSA_(?:do_)?sign\s*\(|\bEVP_PKEY_EC\b|\bEVP_EC_gen\s*\(")
_r("c.kex", "OpenSSL ECDH / DH / X25519", "ECDH/DH", "key-agree", K, H, "c",
   r"\bECDH_compute_key\s*\(|\bDH_(?:generate_key|compute_key)\s*\(|\bEVP_PKEY_(?:X25519|X448|DH)\b")
_r("c.ed25519", "OpenSSL Ed25519 / Ed448", "Ed25519", "signature", S, M, "c",
   r"\bEVP_PKEY_ED(?:25519|448)\b")
_r("c.weak", "MD5 / SHA-1 / DES / RC4 / old TLS", "MD5/SHA-1/DES", "hash", W, M, "c",
   r"\b(?:MD5|SHA1)(?:_Init)?\s*\(|\bEVP_(?:md5|sha1|des_\w+|rc4)\s*\(|\b(?:TLSv1|TLSv1_1|SSLv3)_(?:client_|server_)?method\s*\(")

# Rust
_r("rs.rsa", "RSA (rsa crate / ring)", "RSA", "pke", KEY, H, "rust",
   r"\bRsaPrivateKey::new\s*\(|\bRsaKeyPair::from_\w+\s*\(|\bOaep::new\b|\bPkcs1v15Encrypt\b")
_r("rs.ecdsa", "ECDSA (p256 / k256 / ring)", "ECDSA", "signature", S, M, "rust",
   r"\b(?:p256|p384|k256)::ecdsa\b|\bEcdsaKeyPair::\w+\s*\(")
_r("rs.x25519", "X25519 / ECDH", "X25519", "key-agree", K, H, "rust",
   r"\bx25519_dalek\b|\b(?:EphemeralSecret|StaticSecret)::\w+\s*\(|\bagreement::X25519\b|\bp256::ecdh\b")
_r("rs.ed25519", "Ed25519", "Ed25519", "signature", S, M, "rust",
   r"\bed25519_dalek\b|\bEd25519KeyPair::\w+\s*\(")

# Config / any file
_r("cfg.weak-tls", "TLS 1.0 / 1.1 / SSL enabled in config", "TLS1.0/1.1", "other", W, M, "config",
   r"(?im)^\s*(?:ssl_protocols|SSLProtocol|tls_min_version|min_tls_version|minimum_protocol_version|MinProtocol)\b[^\n]*?\b(?:TLSv1(?:\.[01])?|TLS1_[01]|SSLv[23]|TLSv1_[01])\b(?!\.[23])")
_r("cfg.weak-cipher", "Weak TLS cipher suites", "RC4/DES/3DES/NULL/EXPORT", "other", W, M, "config",
   r"(?im)^\s*(?:ssl_ciphers|SSLCipherSuite|ciphers|cipher_suites)\b[^\n]*\b(?:RC4|DES-CBC3|3DES|NULL|EXPORT|MD5)\b")
_r("cfg.ssh-weak", "SSH configured with RSA/DSA host keys or SHA-1 KEX", "SSH-RSA/DSA", "signature", S, M,
   "config", r"(?im)^\s*(?:HostKeyAlgorithms|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostKey)\b[^\n]*(?:ssh-rsa|ssh-dss|ssh_host_(?:rsa|dsa)_key)")

_r("any.jwt-asym", "Asymmetric JWT / JOSE algorithm", "RS256/ES256/EdDSA", "signature", S, M, ALL_LANGS,
   r"['\"`](?:RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256K?|384|512)|EdDSA)['\"`]", remediation="jwt")
_r("any.private-key", "Private key embedded in file", "private key", "pke", SEC, H, ALL_LANGS,
   r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_r("any.pqc-hybrid-tls", "Hybrid post-quantum TLS group", "X25519MLKEM768", "kem", P, I, ALL_LANGS,
   r"\b(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024|X25519Kyber768(?:Draft00)?)\b",
   quantum_level=3)
_r("any.pqc", "Post-quantum algorithm referenced", "ML-KEM/ML-DSA/SLH-DSA", "kem", P, I, ALL_LANGS,
   r"(?i)\b(?:ML[-_]?KEM(?:[-_]?(?:512|768|1024))?|ML[-_]?DSA(?:[-_]?(?:44|65|87))?|SLH[-_]?DSA|Kyber(?:512|768|1024)?|Dilithium[235]?|SPHINCS\+?|FN[-_]?DSA|Falcon[-_]?(?:512|1024)|X[-_]?Wing|liboqs|\boqs\.(?:KeyEncapsulation|Signature)|BouncyCastlePQCProvider)\b",
   quantum_level=None)


def rules_for(lang: str) -> list[Rule]:
    return [r for r in RULES if lang in r.langs]


def rule_by_id(rule_id: str) -> Rule | None:
    return next((r for r in RULES if r.id == rule_id), None)
