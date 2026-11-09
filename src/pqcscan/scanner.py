"""Walk a directory or ZIP file and run the rules on each file."""

from __future__ import annotations

import bisect
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from . import deps, keys
from .models import Finding, ScanResult
from .rules import Rule, language_for, rules_for

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", ".venv", "venv", "env",
    "__pycache__", ".tox", ".nox", ".mypy_cache", ".pytest_cache", "dist", "build",
    "target", "vendor", ".gradle", ".idea", ".vscode", "site-packages", ".next", ".nuxt",
    "coverage", ".terraform",
}
TEST_MARKERS = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testdata|fixtures?|mocks?)(/|$)|"
                          r"(^|/)(test_[^/]*|[^/]*_test\.(go|py)|[^/]*\.(test|spec)\.[jt]sx?)$",
                          re.IGNORECASE)
COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", ";", "<!--")
SUPPRESS = "pqcscan:ignore"
MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass
class ScanOptions:
    include_tests: bool = True
    scan_deps: bool = True
    scan_keys: bool = True
    max_file_bytes: int = MAX_FILE_BYTES
    exclude: tuple[str, ...] = ()


@dataclass
class SourceFile:
    path: str          # relative, forward slashes
    data: bytes


# File enumeration

def _excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    from fnmatch import fnmatch
    return any(fnmatch(rel, p) or fnmatch(rel.rsplit("/", 1)[-1], p) for p in patterns)


def iter_directory(root: Path, opts: ScanOptions, result: ScanResult) -> Iterator[SourceFile]:
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if _excluded(rel, opts.exclude) or full.is_symlink():
                continue
            try:
                size = full.stat().st_size
                if size > opts.max_file_bytes:
                    result.files_skipped += 1
                    continue
                yield SourceFile(rel, full.read_bytes())
            except OSError as exc:
                result.errors.append(f"{rel}: {exc}")


def iter_zip(path: Path, opts: ScanOptions, result: ScanResult) -> Iterator[SourceFile]:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = info.filename.replace("\\", "/").lstrip("/")
            parts = rel.split("/")
            if ".." in parts or any(p in SKIP_DIRS for p in parts[:-1]):
                continue
            if _excluded(rel, opts.exclude):
                continue
            if info.file_size > opts.max_file_bytes:
                result.files_skipped += 1
                continue
            with zf.open(info) as fh:
                yield SourceFile(rel, fh.read(opts.max_file_bytes + 1))


# Matching

def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(m.end() for m in re.finditer(r"\n", text))
    return starts


def _snippet(line: str, rule: Rule) -> str:
    line = line.strip()
    if rule.id == "any.private-key":
        return line[:60]
    return line if len(line) <= 160 else line[:157] + "..."


def scan_text(rel: str, text: str, lang: str, is_test: bool) -> list[Finding]:
    findings: list[Finding] = []
    starts = _line_starts(text)
    lines = text.split("\n")
    seen: set[tuple[str, int]] = set()
    for rule in rules_for(lang):
        for m in rule.pattern.finditer(text):
            lineno = bisect.bisect_right(starts, m.start())
            if (rule.id, lineno) in seen:
                continue
            seen.add((rule.id, lineno))
            line = lines[lineno - 1] if lineno - 1 < len(lines) else ""
            if SUPPRESS in line:
                continue
            stripped = line.lstrip()
            in_comment = stripped.startswith(COMMENT_PREFIXES) and lang != "config"
            if lang == "config" and stripped.startswith(("#", ";")):
                in_comment = True
            findings.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                kind=rule.kind,
                severity=rule.severity,
                algorithm=rule.algorithm,
                primitive=rule.primitive,
                location=rel,
                line=lineno,
                snippet=_snippet(line, rule),
                language=lang,
                confidence="low" if in_comment else "high",
                context="test" if is_test else ("config" if lang == "config" else "code"),
                remediation=rule.remediation,
                quantum_level=rule.quantum_level,
            ))
    return _drop_redundant_imports(findings, lines)


IMPORT_LINE = re.compile(r"^\s*(?:from\s+\S+\s+import\b|import\s|using\s|#include\b|use\s)")


def _drop_redundant_imports(findings: list[Finding], lines: list[str]) -> list[Finding]:
    """Drop a hit on an import line if the same rule also hit real code in the file."""
    def is_import(f: Finding) -> bool:
        return bool(IMPORT_LINE.match(lines[f.line - 1])) if 0 < f.line <= len(lines) else False

    used = {f.rule_id for f in findings if not is_import(f)}
    return [f for f in findings if not (is_import(f) and f.rule_id in used)]


def _decode(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_file(sf: SourceFile, opts: ScanOptions) -> list[Finding] | None:
    """Return findings for one file, or None if the file type is not scanned."""
    is_test = bool(TEST_MARKERS.search(sf.path))
    if is_test and not opts.include_tests:
        return None
    out: list[Finding] = []
    handled = False

    if opts.scan_keys and keys.is_key_file(sf.path, sf.data):
        out.extend(keys.scan_key_file(sf.path, sf.data))
        handled = True
    if opts.scan_deps and deps.is_manifest(sf.path):
        text = _decode(sf.data)
        if text is not None:
            out.extend(deps.scan_manifest(sf.path, text))
        handled = True

    lang = language_for(sf.path)
    if lang and not (handled and keys.is_key_file(sf.path, sf.data)):
        text = _decode(sf.data)
        if text is not None:
            out.extend(scan_text(sf.path, text, lang, is_test))
            handled = True
    if is_test:
        for f in out:
            f.context = "test"
    return out if handled else None


def scan_path(target: str | Path, opts: ScanOptions | None = None) -> ScanResult:
    opts = opts or ScanOptions()
    path = Path(target)
    result = ScanResult(target=str(target))
    if path.is_file() and zipfile.is_zipfile(path):
        files = iter_zip(path, opts, result)
    elif path.is_dir():
        files = iter_directory(path, opts, result)
    elif path.is_file():
        files = iter([SourceFile(path.name, path.read_bytes())])
    else:
        raise FileNotFoundError(f"No such file or directory: {target}")

    for sf in files:
        found = scan_file(sf, opts)
        if found is None:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        result.findings.extend(found)
    return result


def scan_bytes_zip(data: bytes, opts: ScanOptions | None = None) -> ScanResult:
    """Scan an in-memory ZIP (used by tests and integrations)."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(data)
    try:
        return scan_path(tmp.name, opts)
    finally:
        os.unlink(tmp.name)


__all__ = ["ScanOptions", "scan_path", "scan_text", "scan_bytes_zip"]
