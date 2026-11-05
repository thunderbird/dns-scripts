#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Find the DNS provider of a domain from its nameservers (issue #31).

Looks up the NS records of the domain's zone and matches each nameserver
hostname against the suffixes in nameservers.json. If the domain itself has no
NS records (for example mail.example.com), it walks up one label at a time until
it finds the zone.

Usage:
    uv run dns_provider.py glamrocnamecheap.com
    uv run dns_provider.py glamrocnamecheap.com --quiet
    uv run dns_provider.py example.com --resolver 8.8.8.8

The default output is a short report: the provider, the zone, and every
nameserver with the provider it belongs to. --quiet prints only the provider key
(one line per provider, or "unknown"), for scripts.

Exit status: 0 if at least one nameserver matches a known provider, 1 if none
match or no NS records were found, 2 if the domain is not a valid hostname.

The matching logic (zone_candidates / match_nameserver / detect_provider /
fixes_for) has a JavaScript twin in app.js, so the web app finds the same
provider. Keep the two identical: tests/test_parity.py compares them.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import dns.exception
import dns.name
import dns.resolver

from verify_thundermail_dns import build_resolver, sanitize, valid_domain

NAMESERVERS_PATH = Path(__file__).parent / "nameservers.json"


def load_table() -> list[dict]:
    return json.loads(NAMESERVERS_PATH.read_text())["providers"]


def zone_candidates(domain: str) -> list[str]:
    """The names to try for NS records, most specific first, stopping above the
    TLD: mail.example.com -> [mail.example.com, example.com]. Kept in sync with
    zoneCandidates() in app.js."""
    labels = domain.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _label_matches(label: str, pattern: str) -> bool:
    """One DNS label against one suffix label; a single '*' matches any run."""
    if "*" not in pattern:
        return label == pattern
    head, _, tail = pattern.partition("*")
    return (len(label) >= len(head) + len(tail)
            and label.startswith(head) and label.endswith(tail))


def match_nameserver(host: str, table: list[dict]) -> dict | None:
    """The first table entry with a suffix that matches the END of `host`, label by
    label, or None. Label-aligned, so 'ovh.net' never matches 'xovh.net'. Kept in
    sync with matchNameserver() in app.js."""
    labels = host.lower().rstrip(".").split(".")
    for entry in table:
        for suffix in entry["suffixes"]:
            pats = suffix.split(".")
            if len(pats) <= len(labels) and all(
                    _label_matches(lbl, pat) for lbl, pat in zip(labels[-len(pats):], pats)):
                return entry
    return None


def detect_provider(hosts: list[str], table: list[dict]) -> dict:
    """Match every nameserver. Returns the nameservers (each with its provider key
    or None), the distinct providers in first-seen order, and whether any
    nameserver was unknown. Nameservers are sorted, so the answer order of the
    resolver does not matter. More than one provider usually means a provider move
    is in progress. Kept in sync with detectProvider() in app.js: the result must
    be identical JSON."""
    nameservers, providers, seen = [], [], set()
    for host in sorted(hosts):
        entry = match_nameserver(host, table)
        nameservers.append({"host": host, "key": entry["key"] if entry else None})
        if entry and entry["key"] not in seen:
            seen.add(entry["key"])
            providers.append({"key": entry["key"], "name": entry["name"],
                              "fixes": entry.get("fixes")})
    return {"nameservers": nameservers, "providers": providers,
            "unknown": any(ns["key"] is None for ns in nameservers)}


def fixes_for(result: dict) -> str | None:
    """The records.json provider block to show for this result: only when all the
    nameservers belong to ONE known provider that has a block. Kept in sync with
    fixesFor() in app.js."""
    provs = result["providers"]
    if len(provs) == 1 and not result["unknown"]:
        return provs[0]["fixes"]
    return None


def fallback_reason(result: dict) -> str:
    """Why fixes_for() returned None, for the one line the checker prints when
    --provider auto falls back to generic."""
    provs = result["providers"]
    if not result["nameservers"]:
        return "no NS records found"
    if not provs:
        return "the nameservers are not in nameservers.json"
    if len(provs) > 1 or result["unknown"]:
        return "the nameservers belong to more than one provider"
    return f"there are no fix steps for {provs[0]['name']} yet"


def ns_lookup(resolver: dns.resolver.Resolver, name: str) -> list[str] | None:
    """NS hostnames AT `name` (not via a CNAME), or None if there are none."""
    try:
        answer = resolver.resolve(name, "NS")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return None
    if answer.canonical_name != dns.name.from_text(name):
        return None  # followed a CNAME: those NS records belong to another zone
    return [sanitize(r.target.to_text().rstrip(".").lower()) for r in answer]


def find_nameservers(domain: str, lookup) -> tuple[str | None, list[str]]:
    """(zone, nameservers) for the closest enclosing zone that has NS records, or
    (None, []). `lookup(name)` returns a list of hosts or None."""
    for name in zone_candidates(domain):
        hosts = lookup(name)
        if hosts:
            return name, hosts
    return None, []


def detect(domain: str, resolver: dns.resolver.Resolver, table: list[dict]):
    """(zone, result) for `domain`, doing the lookups."""
    zone, hosts = find_nameservers(domain, lambda n: ns_lookup(resolver, n))
    return zone, detect_provider(hosts, table)


def report(domain: str, zone: str | None, result: dict, table: list[dict]) -> list[str]:
    names = {e["key"]: e["name"] for e in table}
    if not result["nameservers"]:
        return [f"DNS provider for {domain}: unknown (no NS records found)"]
    provs = result["providers"]
    summary = " + ".join(p["name"] for p in provs) or "unknown"
    if provs and result["unknown"]:
        summary += " + unknown"
    lines = [f"DNS provider for {domain}: {summary}"]
    if zone != domain:
        lines.append(f"Zone: {zone}")
    lines.append("Nameservers:")
    width = max(len(ns["host"]) for ns in result["nameservers"])
    for ns in result["nameservers"]:
        lines.append(f"  {ns['host']:<{width}}  {names[ns['key']] if ns['key'] else '(unknown)'}")
    fixes = fixes_for(result)
    if fixes:
        lines.append(f"Fix steps: uv run verify_thundermail_dns.py {domain} --provider {fixes}")
    if result["unknown"]:
        lines.append("To recognize an unknown nameserver, add its suffix to nameservers.json.")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Find the DNS provider of a domain.")
    parser.add_argument("domain", help="domain or hostname, e.g. glamrocnamecheap.com")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help='print only the provider key (one per line, or "unknown")')
    parser.add_argument(
        "--resolver",
        default=os.environ.get("DNS_RESOLVER", "1.1.1.1"),
        help="resolver IP or hostname to query (default: $DNS_RESOLVER or 1.1.1.1)",
    )
    args = parser.parse_args()

    domain = args.domain.strip().rstrip(".").lower()
    if not valid_domain(domain):
        print(f"error: {sanitize(args.domain)!r} is not a valid domain name",
              file=sys.stderr)
        return 2

    table = load_table()
    zone, result = detect(domain, build_resolver(args.resolver), table)
    if args.quiet:
        keys = [p["key"] for p in result["providers"]] or ["unknown"]
        print("\n".join(keys))
    else:
        print("\n".join(report(domain, zone, result, table)))
    return 0 if result["providers"] else 1


if __name__ == "__main__":
    sys.exit(main())
