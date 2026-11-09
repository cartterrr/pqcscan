"""The pqcscan command."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from . import __version__, report
from .models import ScanResult
from .rules import RULES
from .scanner import ScanOptions, scan_path

FORMATS = {
    "text": None, "json": report.to_json, "sarif": report.to_sarif,
    "cbom": report.to_cbom, "md": report.to_markdown,
}
OUT_DIR_FILES = {"json": "pqc-report.json", "sarif": "pqc-report.sarif",
                 "cbom": "cbom.cdx.json", "md": "pqc-report.md"}
FAIL_LEVELS = {"high": 3, "medium": 2, "low": 1, "never": 99}


def _emit(result: ScanResult, fmt: str, output: str | None, out_dir: str | None,
          verbose: bool) -> None:
    if out_dir:
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        for key, name in OUT_DIR_FILES.items():
            (d / name).write_text(FORMATS[key](result), encoding="utf-8")
        click.echo(report.to_text(result, color=sys.stdout.isatty(), verbose=verbose))
        click.echo(f"\nReports written to {d}/: " + ", ".join(OUT_DIR_FILES.values()))
        return
    if fmt == "text":
        text = report.to_text(result, color=output is None and sys.stdout.isatty(),
                              verbose=verbose)
    else:
        text = FORMATS[fmt](result)
    if output:
        Path(output).write_text(text, encoding="utf-8")
        click.echo(f"Wrote {fmt} report to {output}", err=True)
    else:
        click.echo(text)


def _exit_code(result: ScanResult, fail_on: str) -> int:
    threshold = FAIL_LEVELS[fail_on]
    worst = max((f.severity.rank for f in result.findings
                 if f.confidence != "low" and f.context != "test"), default=0)
    return 1 if worst >= threshold else 0


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="pqcscan")
def main():
    """Find crypto that quantum computers will break, and plan what to fix first."""


_common = [
    click.option("-f", "--format", "fmt", type=click.Choice(list(FORMATS)), default="text",
                 show_default=True, help="Output format."),
    click.option("-o", "--output", type=click.Path(dir_okay=False), help="Write to a file."),
    click.option("--out-dir", type=click.Path(file_okay=False),
                 help="Write JSON, SARIF, CBOM and Markdown reports into this directory."),
    click.option("--fail-on", type=click.Choice(list(FAIL_LEVELS)), default="never",
                 show_default=True,
                 help="Exit with code 1 if a finding of this severity or higher exists "
                      "(test files and comment matches are ignored)."),
    click.option("-v", "--verbose", is_flag=True, help="Also show info findings and extra details."),
]


def common(f):
    for opt in reversed(_common):
        f = opt(f)
    return f


@main.command()
@click.argument("target", type=click.Path(exists=True))
@common
@click.option("--no-tests", is_flag=True, help="Skip test files and fixtures.")
@click.option("--no-deps", is_flag=True, help="Skip dependency manifests.")
@click.option("--no-keys", is_flag=True, help="Skip key and certificate files.")
@click.option("-x", "--exclude", multiple=True, metavar="GLOB",
              help="Exclude paths matching this glob (repeatable).")
def scan(target, fmt, output, out_dir, fail_on, verbose, no_tests, no_deps, no_keys, exclude):
    """Scan a directory, a single file or a .zip."""
    opts = ScanOptions(include_tests=not no_tests, scan_deps=not no_deps,
                       scan_keys=not no_keys, exclude=tuple(exclude))
    result = scan_path(target, opts)
    _emit(result, fmt, output, out_dir, verbose)
    sys.exit(_exit_code(result, fail_on))


@main.command()
@click.argument("targets", nargs=-1, required=True)
@common
@click.option("--timeout", default=8.0, show_default=True, help="Seconds per connection.")
@click.option("--no-legacy-check", is_flag=True, help="Do not test for TLS 1.0/1.1.")
def tls(targets, fmt, output, out_dir, fail_on, verbose, timeout, no_legacy_check):
    """Check TLS servers (host, host:port or https://URL).

    Shows whether the server accepts hybrid post-quantum key exchange
    (X25519MLKEM768), what key its certificate uses and when it expires, and
    whether TLS 1.0/1.1 still work. Only run it against servers you own or
    are allowed to test.
    """
    from .tls import scan_endpoints
    result = scan_endpoints(list(targets), timeout=timeout, check_legacy=not no_legacy_check)
    _emit(result, fmt, output, out_dir, verbose)
    if result.errors and not result.findings:
        sys.exit(2)
    sys.exit(_exit_code(result, fail_on))


@main.command("rules")
def list_rules():
    """Print all source-code rules."""
    for r in RULES:
        langs = ",".join(sorted(r.langs)) if len(r.langs) < 4 else "all"
        sev = r.severity.value
        click.echo(f"{r.id:24} {sev:6} {r.kind.value:15} {langs:12} {r.title}")
    click.echo(f"\n{len(RULES)} source rules + key/certificate, dependency and TLS checks.")


@main.command()
@click.option("--port", default=8765, show_default=True, help="Port on 127.0.0.1.")
@click.option("--no-browser", is_flag=True, help="Don't open the browser automatically.")
def ui(port, no_browser):
    """Open the web interface in your browser.

    The server only listens on 127.0.0.1, so nothing outside this computer can
    reach it. Stop it with Ctrl+C.
    """
    from .server import run
    try:
        run(port=port, open_browser=not no_browser)
    except OSError as exc:
        raise click.ClickException(f"can't listen on port {port} ({exc}); try --port 8766")


if __name__ == "__main__":
    main()
