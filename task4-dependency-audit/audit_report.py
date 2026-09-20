#!/usr/bin/env python3
"""Parse `npm audit --json` output into a CSV and a JSON report.

    # run the audit and write both reports
    ./audit_report.py --run --csv reports/vulnerabilities.csv --json reports/audit-report.json

    # re-parse a saved audit, high and critical only
    ./audit_report.py --input reports/npm-audit.json --min-severity high

    # CI gate: non-zero exit when anything critical is present
    ./audit_report.py --run --fail-on critical

Reads npm v7+ output (the `vulnerabilities` object) and falls back to the npm v6
schema (`advisories`), so it keeps working against older lockfiles and CI images.

"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = ["info", "low", "moderate", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

CSV_COLUMNS = [
    "package",
    "severity",
    "cvss_score",
    "is_direct",
    "vulnerable_range",
    "fix_version",
    "fix_is_breaking",
    "advisory_count",
    "titles",
    "cwes",
    "advisory_urls",
    "affects",
]


@dataclass
class Advisory:
    """One security advisory against one package."""

    title: str = ""
    url: str = ""
    severity: str = "info"
    cvss_score: float | None = None
    cwes: list[str] = field(default_factory=list)
    vulnerable_range: str = ""


@dataclass
class Finding:
    """Everything known about one vulnerable package."""

    package: str
    severity: str
    is_direct: bool
    vulnerable_range: str
    fix_version: str | None
    fix_is_breaking: bool
    fix_available: bool
    advisories: list[Advisory] = field(default_factory=list)
    # Packages that pull this one in / are broken by it. Explains why a package
    # nobody installed on purpose shows up in the report.
    affects: list[str] = field(default_factory=list)

    @property
    def cvss_score(self) -> float | None:
        scores = [a.cvss_score for a in self.advisories if a.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def sort_key(self) -> tuple:
        # Worst first: severity, then CVSS, then direct dependencies (which the
        # team can act on immediately), then name for stable ordering.
        return (
            -SEVERITY_RANK.get(self.severity, 0),
            -(self.cvss_score or 0.0),
            not self.is_direct,
            self.package,
        )

    def csv_row(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "severity": self.severity,
            "cvss_score": self.cvss_score if self.cvss_score is not None else "",
            "is_direct": "yes" if self.is_direct else "no",
            "vulnerable_range": self.vulnerable_range,
            "fix_version": self.fix_version or "",
            "fix_is_breaking": "yes" if self.fix_is_breaking else "no",
            "advisory_count": len(self.advisories),
            "titles": " | ".join(a.title for a in self.advisories if a.title),
            "cwes": " ".join(sorted({c for a in self.advisories for c in a.cwes})),
            "advisory_urls": " ".join(a.url for a in self.advisories if a.url),
            "affects": " ".join(self.affects),
        }


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #


def run_npm_audit(project_dir: Path) -> dict[str, Any]:
    """Run `npm audit --json` and return the parsed document.

    npm exits non-zero when it finds vulnerabilities, which is the normal case
    here, so the exit status is deliberately not treated as an error. A
    genuinely failed run is detected by the output not being JSON.
    """
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm not found on PATH; use --input with a saved audit file")

    proc = subprocess.run(
        [npm, "audit", "--json"],
        cwd=project_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if not proc.stdout.strip():
        raise SystemExit(f"npm audit produced no output:\n{proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"could not parse npm audit output ({exc}); npm said:\n{proc.stderr.strip()}"
        ) from exc


def load_audit(path: Path) -> dict[str, Any]:
    text = sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} is not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse(document: dict[str, Any]) -> list[Finding]:
    if "vulnerabilities" in document and isinstance(document["vulnerabilities"], dict):
        return _parse_v7(document["vulnerabilities"])
    if "advisories" in document:
        return _parse_v6(document["advisories"])
    raise SystemExit(
        "unrecognised audit format: expected an npm v7+ 'vulnerabilities' object "
        "or an npm v6 'advisories' object"
    )


def _parse_v7(vulnerabilities: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    for name, entry in vulnerabilities.items():
        advisories: list[Advisory] = []
        via_packages: list[str] = []

        for via in entry.get("via", []):
            if isinstance(via, str):
                # A bare name means "vulnerable only because this dependency is".
                via_packages.append(via)
                continue
            cvss = via.get("cvss") or {}
            advisories.append(
                Advisory(
                    title=via.get("title", ""),
                    url=via.get("url", ""),
                    severity=via.get("severity", entry.get("severity", "info")),
                    cvss_score=cvss.get("score"),
                    cwes=list(via.get("cwe", []) or []),
                    vulnerable_range=via.get("range", ""),
                )
            )

        fix = entry.get("fixAvailable", False)
        fix_version, fix_breaking = None, False
        if isinstance(fix, dict):
            fix_version = fix.get("version")
            fix_breaking = bool(fix.get("isSemVerMajor"))

        affects = list(entry.get("effects", []) or [])
        if not advisories and via_packages:
            # Keep the explanation for an indirect finding rather than emitting a
            # row with no reason attached.
            affects = sorted(set(affects) | {f"via:{p}" for p in via_packages})

        findings.append(
            Finding(
                package=name,
                severity=entry.get("severity", "info"),
                is_direct=bool(entry.get("isDirect")),
                vulnerable_range=entry.get("range", ""),
                fix_version=fix_version,
                fix_is_breaking=fix_breaking,
                fix_available=bool(fix),
                advisories=advisories,
                affects=affects,
            )
        )

    return sorted(findings, key=lambda f: f.sort_key)


def _parse_v6(advisories: dict[str, Any]) -> list[Finding]:
    """npm v6 keyed advisories, one entry per advisory rather than per package."""
    merged: dict[str, Finding] = {}

    for advisory in advisories.values():
        name = advisory.get("module_name", "unknown")
        found = advisory.get("findings", [{}])
        is_direct = any(
            len(path.split(">")) == 1
            for finding in found
            for path in finding.get("paths", [])
        )

        item = Advisory(
            title=advisory.get("title", ""),
            url=advisory.get("url", ""),
            severity=advisory.get("severity", "info"),
            cvss_score=(advisory.get("cvss") or {}).get("score"),
            cwes=[advisory["cwe"]] if advisory.get("cwe") else [],
            vulnerable_range=advisory.get("vulnerable_versions", ""),
        )

        existing = merged.get(name)
        if existing is None:
            merged[name] = Finding(
                package=name,
                severity=advisory.get("severity", "info"),
                is_direct=is_direct,
                vulnerable_range=advisory.get("vulnerable_versions", ""),
                fix_version=advisory.get("patched_versions"),
                fix_is_breaking=False,  # v6 does not say; assume non-breaking
                fix_available=bool(advisory.get("patched_versions")),
                advisories=[item],
            )
        else:
            existing.advisories.append(item)
            if SEVERITY_RANK.get(item.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                existing.severity = item.severity

    return sorted(merged.values(), key=lambda f: f.sort_key)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def summarise(findings: list[Finding]) -> dict[str, Any]:
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    fixable = [f for f in findings if f.fix_available]
    non_breaking = [f for f in fixable if not f.fix_is_breaking]
    breaking = [f for f in fixable if f.fix_is_breaking]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "vulnerable_packages": len(findings),
        "advisories": sum(len(f.advisories) for f in findings),
        "by_severity": by_severity,
        "direct_dependencies": sum(1 for f in findings if f.is_direct),
        "transitive_dependencies": sum(1 for f in findings if not f.is_direct),
        "fixable": len(fixable),
        "fixable_without_breaking_change": len(non_breaking),
        "fixable_only_with_major_upgrade": len(breaking),
        "not_fixable": len(findings) - len(fixable),
        "packages_requiring_major_upgrade": sorted(f.package for f in breaking),
    }


def write_csv(path: Path, findings: Iterable[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.csv_row())


def write_json(path: Path, summary: dict[str, Any], findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"summary": summary, "findings": [asdict(f) | {"cvss_score": f.cvss_score} for f in findings]}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def print_table(summary: dict[str, Any], findings: list[Finding], stream=sys.stdout) -> None:
    counts = summary["by_severity"]
    print(
        "\n{} vulnerable packages  (critical {}, high {}, moderate {}, low {})".format(
            summary["vulnerable_packages"],
            counts["critical"],
            counts["high"],
            counts["moderate"],
            counts["low"],
        ),
        file=stream,
    )
    print(
        "{} fixable: {} without a breaking change, {} require a major upgrade\n".format(
            summary["fixable"],
            summary["fixable_without_breaking_change"],
            summary["fixable_only_with_major_upgrade"],
        ),
        file=stream,
    )

    header = f"{'PACKAGE':<22}{'SEVERITY':<10}{'CVSS':<7}{'DIRECT':<8}{'FIX':<12}BREAKING"
    print(header, file=stream)
    print("-" * len(header), file=stream)
    for f in findings:
        print(
            f"{f.package[:21]:<22}{f.severity:<10}"
            f"{(f'{f.cvss_score:.1f}' if f.cvss_score else '-'):<7}"
            f"{('yes' if f.is_direct else 'no'):<8}"
            f"{(f.fix_version or ('available' if f.fix_available else 'none')):<12}"
            f"{'yes' if f.fix_is_breaking else 'no'}",
            file=stream,
        )
    print("", file=stream)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Turn `npm audit --json` output into a CSV and a JSON report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 clean or below threshold, 1 threshold met, 2 could not run.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="a saved `npm audit --json` file, or - for stdin")
    source.add_argument("--run", action="store_true", help="run `npm audit --json` now (default)")
    parser.add_argument("--project", type=Path, default=Path("."), help="project directory for --run")
    parser.add_argument("--csv", type=Path, help="write the CSV report here")
    parser.add_argument("--json", dest="json_out", type=Path, help="write the JSON report here")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="low",
        help="omit findings below this severity (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="exit 1 if any finding is at or above this severity (CI gate)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the summary table")
    args = parser.parse_args(argv)

    try:
        document = load_audit(args.input) if args.input else run_npm_audit(args.project)
        findings = parse(document)
    except SystemExit as exc:
        print(f"audit_report: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITY_RANK[args.min_severity]
    findings = [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]

    summary = summarise(findings)

    if args.csv:
        write_csv(args.csv, findings)
        print(f"wrote {args.csv} ({len(findings)} rows)", file=sys.stderr)
    if args.json_out:
        write_json(args.json_out, summary, findings)
        print(f"wrote {args.json_out}", file=sys.stderr)
    if not args.csv and not args.json_out and args.quiet:
        json.dump({"summary": summary}, sys.stdout, indent=2)
        print()

    if not args.quiet:
        print_table(summary, findings)

    if args.fail_on:
        gate = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK.get(f.severity, 0) >= gate for f in findings):
            print(
                f"audit_report: failing because findings at or above '{args.fail_on}' are present",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
