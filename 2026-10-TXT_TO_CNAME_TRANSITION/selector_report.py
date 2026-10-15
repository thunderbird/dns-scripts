#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Compare expected and actual DKIM selectors for the custom domains (issue #29).

Runs ./find-selector on every line of custom_domains.txt and prints a Markdown
table: domain | expected selector | actual selector | match. Line N of
custom_domains_selectors.txt holds the expected selector for line N of
custom_domains.txt.

Usage: uv run selector_report.py [report.md]
"""

import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NUMBER_RE = re.compile(r"^\s*\d+\.\s*")  # optional "12. " list prefix
EXPECTED_RE = re.compile(r"Stalwart DKIM:\s*(?:Ed25519\((?P<sel>[^)]+)\)|none)")


def expected_selector(line):
    m = EXPECTED_RE.search(line)
    if not m:
        raise ValueError(f"unrecognised selector line: {line!r}")
    return m.group("sel") or "none"


def actual_selectors(domain):
    proc = subprocess.run(
        ["fish", str(HERE / "find-selector"), domain],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 1:
        return []
    if proc.returncode != 0:
        raise RuntimeError(f"find-selector {domain} exited {proc.returncode}: {proc.stderr.strip()}")
    return [line.split()[0] for line in proc.stdout.splitlines() if line.strip()]


def main():
    domains = (HERE / "custom_domains.txt").read_text().splitlines()
    expected = (HERE / "custom_domains_selectors.txt").read_text().splitlines()
    domains = [NUMBER_RE.sub("", d).strip() for d in domains if d.strip()]
    expected = [e for e in expected if e.strip()]
    if len(domains) != len(expected):
        sys.exit(f"line count mismatch: {len(domains)} domains, {len(expected)} selectors")

    rows = ["| domain | expected selector | actual selector | match |", "|---|---|---|---|"]
    matches = 0
    for domain, line in zip(domains, expected):
        want = expected_selector(line)
        got = actual_selectors(domain)
        ok = want in got if got else want == "none"
        matches += ok
        rows.append(f"| {domain} | {want} | {', '.join(got) or 'none'} | {'✓' if ok else '✗'} |")
        print(f"{domain}: done", file=sys.stderr)

    report = "\n".join(rows) + f"\n\n{matches}/{len(domains)} match\n"
    print(report, end="")
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(report)


if __name__ == "__main__":
    main()
