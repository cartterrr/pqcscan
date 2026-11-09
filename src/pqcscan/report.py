"""Output formats: text, JSON, SARIF 2.1.0, CycloneDX 1.6 CBOM, Markdown."""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid

from . import __version__
from .models import KIND_LABELS, Finding, Kind, ScanResult, Severity
from .plan import DEADLINES, build_plan
from .rules import rule_by_id

TOOL = "pqcscan"
REPO_URL = "https://github.com/cartterrr/pqcscan"
SEV_ORDER = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _loc(f: Finding) -> str:
    return f"{f.location}:{f.line}" if f.line else f.location


# JSON

def to_json(result: ScanResult) -> str:
    plan = build_plan(result)
    doc = {
        "tool": {"name": TOOL, "version": __version__},
        "generated_at": _now(),
        "target": result.target,
        "stats": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "by_severity": result.count_by("severity"),
            "by_kind": result.count_by("kind"),
        },
        "findings": [f.to_dict() for f in result.sorted()],
        "plan": [
            {"wave": w.key, "title": w.title, "when": w.when, "why": w.why,
             "items": [{"title": i.title, "algorithm": i.algorithm, "severity": i.severity.value,
                        "count": i.count, "locations": i.locations, "remediation": i.remediation}
                       for i in w.items]}
            for w in plan
        ],
        "errors": result.errors,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# SARIF (GitHub code scanning)

_SARIF_LEVEL = {Severity.HIGH: "error", Severity.MEDIUM: "warning",
                Severity.LOW: "note", Severity.INFO: "note"}
_SECURITY_SEVERITY = {Severity.HIGH: "7.5", Severity.MEDIUM: "5.0",
                      Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_sarif(result: ScanResult, include_info: bool = False) -> str:
    findings = [f for f in result.sorted() if include_info or f.severity != Severity.INFO]
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules:
            r = rule_by_id(f.rule_id)
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": re.sub(r"[^A-Za-z0-9]", "", f.title.title())[:64] or f.rule_id,
                "shortDescription": {"text": r.title if r else f.title},
                "fullDescription": {"text": f.remediation},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", "cryptography", "post-quantum", f.kind.value],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "precision": "medium",
                },
            }
        phys = {"artifactLocation": {"uri": f.location}}
        if f.line:
            phys["region"] = {"startLine": f.line}
            if f.snippet:
                phys["region"]["snippet"] = {"text": f.snippet}
        msg = f"{f.title} ({f.algorithm})."
        if f.detail:
            msg += f" {f.detail}."
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": msg},
            "locations": [{"physicalLocation": phys}],
            "properties": {"kind": f.kind.value, "confidence": f.confidence, "context": f.context},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL, "version": __version__,
                                "informationUri": REPO_URL, "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# CycloneDX 1.6 CBOM

_FUNCTIONS = {
    "pke": ["keygen", "encrypt", "decrypt"], "signature": ["sign", "verify"],
    "key-agree": ["keygen", "keyderive"], "kem": ["keygen", "encapsulate", "decapsulate"],
    "hash": ["digest"], "block-cipher": ["encrypt", "decrypt"],
}
_PURL_TYPE = {"pypi": "pypi", "npm": "npm", "go": "golang", "maven": "maven",
              "cargo": "cargo", "gem": "gem", "composer": "composer"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "x"


def _occ(f: Finding) -> dict:
    o = {"location": f.location}
    if f.line:
        o["line"] = f.line
    ctx = f.snippet or f.detail
    if ctx:
        o["additionalContext"] = ctx
    return o


def to_cbom(result: ScanResult) -> str:
    components: dict[str, dict] = {}

    def add(ref: str, factory, f: Finding):
        comp = components.get(ref)
        if comp is None:
            comp = factory()
            comp["bom-ref"] = ref
            comp.setdefault("evidence", {"occurrences": []})
            components[ref] = comp
        comp["evidence"]["occurrences"].append(_occ(f))

    for f in result.sorted():
        if f.rule_id == "key.trust-bundle":
            continue                      # a summary row, not an asset of its own
        if f.rule_id.startswith("dep."):
            eco = f.detail.split(" ", 1)[0]
            ref = f"pkg:{_PURL_TYPE.get(eco, eco)}/{f.algorithm}"

            def lib(f=f, ref=ref, eco=eco):
                comp = {"type": "library", "name": f.algorithm, "description": f.title}
                if eco != "maven":          # maven purls need a groupId we do not know
                    comp["purl"] = ref
                return comp
            add(ref, lib, f)
        elif f.rule_id in ("key.certificate",):
            cn = f.extra.get("subject_cn", "certificate")
            ref = f"crypto/certificate/{_slug(cn)}@{f.extra.get('not_after', '')}"
            add(ref, lambda f=f, cn=cn: {
                "type": "cryptographic-asset", "name": str(cn),
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": str(cn),
                        "notValidAfter": f.extra.get("not_after", "") + "T00:00:00Z",
                        "certificateFormat": "X.509",
                    },
                },
                "properties": [
                    {"name": "pqcscan:publicKeyAlgorithm", "value": f.algorithm},
                    {"name": "pqcscan:signatureAlgorithm",
                     "value": str(f.extra.get("signature_algorithm", ""))},
                ]}, f)
        elif f.kind == Kind.SECRET or f.rule_id in ("key.public-key", "key.ssh-public-key"):
            mtype = "private-key" if f.kind == Kind.SECRET else "public-key"
            ref = f"crypto/related-crypto-material/{mtype}/{_slug(f.location)}-{f.line}"
            props = {"type": mtype}
            if f.extra.get("key_size"):
                props["size"] = f.extra["key_size"]
            add(ref, lambda f=f, props=props, mtype=mtype: {
                "type": "cryptographic-asset", "name": f"{f.algorithm} {mtype}",
                "cryptoProperties": {"assetType": "related-crypto-material",
                                     "relatedCryptoMaterialProperties": props}}, f)
        elif f.rule_id.startswith("tls.") and f.rule_id != "tls.legacy-version":
            ref = f"crypto/protocol/tls/{_slug(f.location)}"
            add(ref, lambda f=f: {
                "type": "cryptographic-asset", "name": f"TLS {f.location}",
                "cryptoProperties": {"assetType": "protocol",
                                     "protocolProperties": {"type": "tls"}},
                "properties": []}, f)
            components[ref]["properties"].append(
                {"name": "pqcscan:keyExchange", "value": f.algorithm})
        else:
            ref = f"crypto/algorithm/{_slug(f.algorithm)}/{f.primitive}"

            def factory(f=f):
                alg_props = {"primitive": f.primitive,
                             "executionEnvironment": "software-plain-ram",
                             "cryptoFunctions": _FUNCTIONS.get(f.primitive, ["other"])}
                if f.quantum_level is not None:
                    alg_props["nistQuantumSecurityLevel"] = f.quantum_level
                return {"type": "cryptographic-asset", "name": f.algorithm,
                        "cryptoProperties": {"assetType": "algorithm",
                                             "algorithmProperties": alg_props},
                        "properties": [{"name": "pqcscan:kind", "value": f.kind.value}]}
            add(ref, factory, f)

    root_ref = "target"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": TOOL,
                                      "version": __version__}]},
            "component": {"type": "application", "name": result.target, "bom-ref": root_ref},
        },
        "components": list(components.values()),
        "dependencies": [{"ref": root_ref, "dependsOn": list(components.keys())}],
    }
    return json.dumps(bom, indent=2, ensure_ascii=False)


# Markdown report

def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def to_markdown(result: ScanResult, max_rows: int = 300) -> str:
    sev = result.count_by("severity")
    kinds = result.count_by("kind")
    out = [
        f"# Post-quantum cryptography report: `{result.target}`",
        "",
        f"Generated by {TOOL} {__version__} on {_now()}. "
        f"Files scanned: {result.files_scanned}.",
        "",
        "> Every match here needs a person to check it, and an empty section doesn't mean "
        "that part is quantum-safe. The scan only sees source, config and key files: compiled "
        "dependencies, HSMs, cloud services and runtime settings aren't covered.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {s.value} | {sev.get(s.value, 0)} |" for s in SEV_ORDER]
    out += ["", "| Category | Count |", "|---|---|"]
    out += [f"| {KIND_LABELS[k]} | {kinds[k.value]} |" for k in Kind if kinds.get(k.value)]

    out += ["", "## Migration plan", ""]
    plan = build_plan(result)
    if not plan:
        out.append("Nothing to migrate was detected.")
    for w in plan:
        out += [f"### {w.title} ({w.when})", "", w.why, ""]
        for item in w.items:
            locs = ", ".join(f"`{l}`" for l in item.locations[:8])
            more = f" and {item.count - 8} more" if item.count > 8 else ""
            out.append(f"- **{item.title}** ({item.algorithm}), {item.count} "
                       f"occurrence{'s' if item.count != 1 else ''}: {locs}{more}")
        advice: dict[str, str] = {}
        for i in w.items:
            advice.setdefault(i.remediation, i.title)
        out.append("")
        if len(advice) == 1:
            out.append(f"**What to do:** {next(iter(advice))}")
        else:
            out.append("**What to do:**")
            out.append("")
            out += [f"- *{title}:* {rem}" for rem, title in advice.items()]
        out.append("")

    out += ["## Deadlines to plan against", "", "| Source | When | What |", "|---|---|---|"]
    out += [f"| {a} | {b} | {c} |" for a, b, c in DEADLINES]

    findings = result.sorted()
    out += ["", f"## Findings ({len(findings)})", "",
            "| Severity | Finding | Algorithm | Location | Context | Evidence |",
            "|---|---|---|---|---|---|"]
    for f in findings[:max_rows]:
        ev = f.snippet or f.detail
        conf = " (low confidence)" if f.confidence == "low" else ""
        out.append(f"| {f.severity.value} | {_md_escape(f.title)}{conf} | {_md_escape(f.algorithm)} "
                   f"| `{_md_escape(_loc(f))}` | {f.context} | `{_md_escape(ev)[:120]}` |")
    if len(findings) > max_rows:
        out.append(f"\n...and {len(findings) - max_rows} more (see JSON output).")
    if result.errors:
        out += ["", "## Errors", ""] + [f"- {e}" for e in result.errors]
    out.append("")
    return "\n".join(out)


# Terminal

def to_text(result: ScanResult, color: bool = True, verbose: bool = False) -> str:
    import click

    def c(s, **kw):
        return click.style(s, **kw) if color else s

    sev_color = {Severity.HIGH: "red", Severity.MEDIUM: "yellow",
                 Severity.LOW: "cyan", Severity.INFO: "bright_black"}
    lines = [c(f"{TOOL} {__version__}", bold=True) + f"  target: {result.target}",
             f"{result.unit} scanned: {result.files_scanned}"
             + (f", skipped: {result.files_skipped}" if result.unit == "files" else ""), ""]
    findings = sorted(result.findings, key=lambda f: (f.location, f.line, -f.severity.rank))
    shown = [f for f in findings if verbose or f.severity != Severity.INFO]
    current = None
    for f in shown:
        if f.location != current:
            current = f.location
            lines.append(c(f.location, bold=True))
        tag = c(f"{f.severity.value.upper():6}", fg=sev_color[f.severity], bold=True)
        where = f"{f.line:>5}" if f.line else "     "
        extra = c(" [test]", fg="bright_black") if f.context == "test" else ""
        extra += c(" [comment?]", fg="bright_black") if f.confidence == "low" else ""
        lines.append(f"  {where}  {tag} {f.title} ({f.algorithm}){extra}")
        if f.detail and (verbose or f.context in ("endpoint", "key-file")):
            lines.append(c(f"         {f.detail}", fg="bright_black"))
    hidden = len(findings) - len(shown)
    sev = result.count_by("severity")
    lines += ["", c("Summary", bold=True) + ": " + ", ".join(
        c(f"{sev.get(s.value, 0)} {s.value}", fg=sev_color[s]) for s in SEV_ORDER)]
    if hidden:
        lines.append(c(f"({hidden} info findings not shown, mostly PQC usage and crypto libraries; "
                       f"use -v to show)", fg="bright_black"))
    plan = build_plan(result)
    if plan:
        lines += ["", c("Migration plan", bold=True)]
        for w in plan:
            n = sum(i.count for i in w.items)
            lines.append(f"  {w.title}: {n} occurrence{'s' if n != 1 else ''} ({w.when})")
    for e in result.errors:
        lines.append(c(f"error: {e}", fg="red"))
    return "\n".join(lines)
