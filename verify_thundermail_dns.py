#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Check that a domain's DNS records match the Thundermail setup.

Verifies the MX record, the JMAP/CalDAV/CardDAV/IMAPS/submission SRV records,
the SPF / MTA-STS / TLSRPT / DMARC TXT records, and the three DKIM CNAMEs.

Usage:
    uv run verify_thundermail_dns.py <domain>
    uv run verify_thundermail_dns.py glamrocnamecheap.com
    uv run verify_thundermail_dns.py glamrocnamecheap.com --provider namecheap
    uv run verify_thundermail_dns.py example.com --bind > example.com.thundermail.zone

Exit status is 0 only if every expected record is present and correct. SRV is
checked relationally rather than against a literal (thunderbird-accounts#1163):
the port and target must match exactly, the weight is not compared at all, and the
priority only has to be a LOWER number than any other target at that name — see
the srv_lowest_priority mode in records.json.

Pass --provider to print exactly what to enter in that DNS provider's control
panel for each FAILING record (accounting for provider quirks such as how the
Host/Name field is written). The supported providers come from records.json.
Fixes print as a compact per-type table by default; --fix-format long gives the
older one-labelled-block-per-record layout.

Pass --bind to print all the records as a BIND zone file fragment (no lookups),
or --bind-failed-only to run the check and print only the failed records as one
(the report then goes to stderr, so stdout holds just the zone file).

The record set, value templates, and per-provider remediation strings all live in
records.json, which is shared verbatim with the browser version (index.html /
app.js) so the two front-ends can never drift apart.

The resolver defaults to 1.1.1.1 (override with --resolver or DNS_RESOLVER) to
avoid stale local caches. The value may be an IP address or a hostname (e.g. an
authoritative nameserver such as dns1.registrar-servers.com), which is resolved
to its address before use.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import dns.rdatatype
import dns.resolver

CONFIG_PATH = Path(__file__).parent / "records.json"

GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
RESET = "\033[0m"

_TOKEN = re.compile(r"\{(\w+)\}")

# Control / terminal-escape bytes to neutralise in any DNS-derived text before
# printing (C0 minus \t\n\r, DEL, and C1). A domain owner controls their record
# contents, so this closes an ANSI-escape-injection path into the terminal.
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Hostname validation (kept in sync with the same regex in app.js). Applied to
# user-supplied domains before any lookup.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

_MAX_VALUE = 200  # cap displayed answer length to avoid pathological output

# How to word a mismatch, per match_mode (kept in sync with app.js).
_VERBS = {"exact": "expected",
          "srv_lowest_priority": "expected (any weight, lowest priority number)"}

# Wording for the "conflict" status: the record is published, but another target at
# the same name can outrank it. Mirrors thunderbird-accounts#1163. (In sync with app.js.)
_CONFLICT = ("conflicts: another target here has an equal or lower priority number — "
             "give the Thundermail target the lowest number (any weight is fine)")


def sanitize(s: str) -> str:
    """Escape control/terminal chars so untrusted DNS data can't drive the tty."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", s)


def valid_domain(domain: str) -> bool:
    return bool(_HOSTNAME.match(domain))


def cap(s: str) -> str:
    return s if len(s) <= _MAX_VALUE else s[:_MAX_VALUE] + "…"


def label(rec: dict) -> str:
    return rec.get("label", rec["host"])


def resolve_record(rec: dict, domain: str) -> dict:
    """Concrete view of a record: {domain} filled in, plus qname/fqdn helpers.

    This is the shared "interpolation contract" — the JS twin in app.js does the
    same thing so templates in records.json render identically on both sides.
    """
    host = rec["host"]
    ctx = {k: (v.replace("{domain}", domain) if isinstance(v, str) else v)
           for k, v in rec.items()}
    ctx["domain"] = domain
    ctx["qname"] = domain if host == "@" else f"{host}.{domain}"
    ctx["fqdn"] = (domain + ".") if host == "@" else f"{host}.{domain}."
    # Relative host label, empty at the apex — for panels (e.g. Cosmotown) whose
    # Host field is left blank for the root domain rather than written as "@".
    ctx["subhost"] = "" if host == "@" else host
    # SRV panels (e.g. GoDaddy) that split the "_service._protocol" label into
    # separate Service/Protocol fields, leaving Name as whatever remains ("@" at
    # the apex, which is where all our SRV records live). Only meaningful for SRV.
    labels = host.split(".")
    ctx["service"] = labels[0]
    ctx["protocol"] = labels[1] if len(labels) > 1 else ""
    ctx["srvhost"] = ".".join(labels[2:]) or "@"
    # Like srvhost but blank (not "@") at the apex — for Hover's SRV form, whose
    # optional Subdomain field is left empty for the root domain.
    ctx["srvsubhost"] = ".".join(labels[2:])
    # Service/protocol WITHOUT the leading underscore — for Plesk-based panels
    # (METANET), whose Service-Name/Protokoll fields are documented as taking the
    # bare name ("Beispiel: SIP (ohne Unterstrich)"): "imaps"/"tcp", not "_imaps"/"_tcp".
    ctx["bareservice"] = ctx["service"].lstrip("_")
    ctx["bareprotocol"] = ctx["protocol"].lstrip("_")
    return ctx


def interpolate(template: str, ctx: dict) -> str:
    """Replace {field} tokens in `template` with values from `ctx`."""
    return _TOKEN.sub(lambda m: str(ctx[m.group(1)]), template)


def value_of(ctx: dict, cfg: dict, key: str) -> str:
    """Render the 'value' (full) or 'match' (substring) string for a record."""
    return interpolate(cfg["value_templates"][ctx["type"]][key], ctx)


def srv_parts(record: str) -> tuple[int, str] | None:
    """(priority, "port target") from an SRV record string: the number the relational
    check compares, and the identity of the service endpoint. None unless the string
    is four space-separated fields with a numeric priority, so a malformed record can
    never match. `[0-9]` rather than `\\d`, which in Python (unlike JS) also matches
    non-ASCII digits — the JS twin must reject exactly the same strings."""
    parts = record.split()
    if len(parts) != 4 or not re.fullmatch(r"[0-9]+", parts[0]):
        return None
    return (int(parts[0]), f"{parts[2]} {parts[3]}")


def check_answers(expected: str, answers: list[str], mode: str) -> str:
    """Status of `expected` against every answer at its name: 'ok', 'missing', or
    (SRV only) 'conflict'.

    mode 'exact' (MX/CNAME) requires a whole-record equality so a target with extra
    labels appended (e.g. a missing trailing dot turning `mail.thundermail.com` into
    `mail.thundermail.com.example.com`) fails; mode 'contains' (TXT) keeps the
    substring test the prefix fragments (MTA-STS/TLSRPT/DMARC) rely on.

    mode 'srv_lowest_priority' (SRV) is the relational rule from
    thunderbird-accounts#1163: port and target must match exactly, the weight is not
    compared (it only splits load between competing targets at the same priority, and
    we publish a single target — plus Plesk/METANET offers only a fixed dropdown of
    weights), and the priority is judged against the other answers instead of against
    our published number: our target must carry a strictly LOWER priority number than
    any other target at that name. So a working setup at priority 10 passes, while our
    record tied with or out-ranked by someone else's is a 'conflict' — it is published
    but may not win. Unparseable answers are ignored for that comparison (they can't be
    ranked), but never match. Case-insensitive; kept in sync with app.js."""
    exp = expected.lower()
    if mode == "exact":
        return "ok" if any(exp == a.lower() for a in answers) else "missing"
    if mode == "srv_lowest_priority":
        want = srv_parts(exp)
        if want is None:
            return "missing"
        parsed = [p for p in (srv_parts(a.lower()) for a in answers) if p is not None]
        ours = [prio for prio, key in parsed if key == want[1]]
        if not ours:
            return "missing"
        best = min(ours)
        outranked = any(prio <= best for prio, key in parsed if key != want[1])
        return "conflict" if outranked else "ok"
    return "ok" if any(exp in a.lower() for a in answers) else "missing"


def failure_text(mode: str, status: str, expected: str) -> str:
    """The FAIL line's explanation: what we wanted, or why what's there conflicts.
    Kept in sync with failureText() in app.js."""
    if status == "conflict":
        return _CONFLICT
    return f"{_VERBS.get(mode, 'expected to contain')}: {expected}"


def render_fix(cfg: dict, provider: str, ctx: dict) -> list[str]:
    """Long form: provider instructions for one record (header + labelled fields)."""
    block = cfg["providers"][provider][ctx["type"]]
    width = max(len(lbl) for lbl, _ in block["fields"]) + 1  # + 1 for the colon
    lines = [block["header"]]
    for lbl, tpl in block["fields"]:
        lines.append(f"    {(lbl + ':'):<{width}} {interpolate(tpl, ctx)}")
    return lines


def render_fix_table(cfg: dict, provider: str, rtype: str, ctxs: list[dict]) -> list[str]:
    """Compact form: provider header, then one column per field and one row per
    failing record of the same type."""
    block = cfg["providers"][provider][rtype]
    labels = [lbl for lbl, _ in block["fields"]]
    rows = [[interpolate(tpl, ctx) for _, tpl in block["fields"]] for ctx in ctxs]
    widths = [max(len(labels[i]), *(len(r[i]) for r in rows)) for i in range(len(labels))]

    def fmt(cells: list[str]) -> str:  # left-align every column but the last
        return "  ".join(c if i == len(cells) - 1 else c.ljust(widths[i])
                         for i, c in enumerate(cells))

    return [block["header"], "", "  " + fmt(labels), *("  " + fmt(r) for r in rows)]


def bind_quote(s: str) -> str:
    """A TXT value as BIND character-strings: double-quoted, with backslash and quote
    escaped, split into 255-character pieces (the most one string can hold). Our
    values are ASCII (the domain passed the hostname regex), so characters are bytes.
    Kept in sync with bindQuote() in app.js."""
    chunks = [s[i:i + 255] for i in range(0, len(s), 255)] or [""]
    return " ".join('"' + c.replace("\\", "\\\\").replace('"', '\\"') + '"'
                    for c in chunks)


def bind_zone(cfg: dict, domain: str, records: list[dict], failed_only: bool = False) -> str:
    """A BIND zone file fragment (no SOA/NS) holding `records`, built from the `bind`
    block of records.json (issue #23). `failed_only` swaps the duplicate-record
    warning for a note that this is only the failed subset. Kept in sync with
    bindZone() in app.js: both must return byte-identical text."""
    bind = cfg["bind"]
    notes = {"domain": domain, "count": len(records)}
    lines = [interpolate(line, notes) for line in bind["header"]]
    lines += [interpolate(line, notes)
              for line in bind["failed_note" if failed_only else "all_note"]]
    # No $TTL: the importing zone's default TTL applies.
    lines += ["", f"$ORIGIN {domain}."]
    rows = []
    for rec in records:
        ctx = resolve_record(rec, domain)
        ctx["match"] = value_of(ctx, cfg, "match")
        ctx["value"] = value_of(ctx, cfg, "value")
        rdata = interpolate(bind["rdata"][rec["type"]], ctx)
        if rec["type"] in bind["quoted"]:
            rdata = bind_quote(rdata)
        rows.append((rec["host"], rec["type"], rdata))
    width = max((len(host) for host, _, _ in rows), default=0)
    lines += [f"{host:<{width}}  IN {rtype:<5} {rdata}" for host, rtype, rdata in rows]
    return "\n".join(lines) + "\n"


def build_resolver(server: str) -> dns.resolver.Resolver:
    """Return a resolver that queries `server` (IP or hostname) explicitly."""
    resolver = dns.resolver.Resolver(configure=False)
    try:
        # Accept a hostname (e.g. an authoritative NS) by resolving it first,
        # using the system resolver for that one lookup.
        addresses = [str(a) for a in dns.resolver.resolve(server, "A")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        # Assume `server` is already an IP address.
        addresses = [server]
    resolver.nameservers = addresses
    return resolver


def query(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    """Return answer records as strings, trailing dots trimmed (empty on none)."""
    try:
        answers = resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []
    return [sanitize(answer.to_text().strip('"').rstrip(".")) for answer in answers]


def main() -> int:
    cfg = json.loads(CONFIG_PATH.read_text())
    providers = sorted(cfg["providers"])

    parser = argparse.ArgumentParser(
        description="Verify a domain's DNS matches the Thundermail setup.",
    )
    parser.add_argument("domain", help="domain to check, e.g. glamrocnamecheap.com")
    parser.add_argument(
        "--provider",
        choices=providers,
        help="print how to fix each FAILING record in this DNS provider's panel",
    )
    parser.add_argument(
        "--resolver",
        default=os.environ.get("DNS_RESOLVER", "1.1.1.1"),
        help="resolver IP or hostname to query (default: $DNS_RESOLVER or 1.1.1.1)",
    )
    parser.add_argument(
        "--fix-format",
        choices=("table", "long"),
        default="table",
        help="layout for --provider fixes: compact 'table' (default) or 'long' "
        "(one labelled block per record)",
    )
    parser.add_argument(
        "--bind",
        action="store_true",
        help="print all the Thundermail records as a BIND zone file fragment and exit "
        "(no DNS lookups)",
    )
    parser.add_argument(
        "--bind-failed-only",
        action="store_true",
        help="run the check, then print only the FAILED records as a BIND zone file "
        "fragment on stdout (the check report goes to stderr)",
    )
    args = parser.parse_args()

    domain = args.domain.strip().rstrip(".")
    if not valid_domain(domain):
        print(f"error: {sanitize(args.domain)!r} is not a valid domain name",
              file=sys.stderr)
        return 2

    if args.bind and not args.bind_failed_only:
        sys.stdout.write(bind_zone(cfg, domain, cfg["records"]))
        return 0

    # With --bind-failed-only, stdout carries the zone file, so the report moves to
    # stderr: `> thundermail.zone` then captures only the records.
    report = sys.stderr if args.bind_failed_only else sys.stdout

    def say(*parts, **kwargs):
        print(*parts, file=report, **kwargs)

    resolver = build_resolver(args.resolver)

    say(f"Verifying Thundermail DNS for {domain} (resolver {sanitize(args.resolver)})\n")

    passed = 0
    failures = []
    failed_records = []  # raw records, for --bind-failed-only
    current_group = None
    for rec in cfg["records"]:
        if rec["type"] != current_group:
            current_group = rec["type"]
            say(cfg["group_headers"][current_group])

        ctx = resolve_record(rec, domain)
        # Enrich with the derived match/value strings so provider templates can
        # reference {match} / {value} uniformly across record types.
        expected = ctx["match"] = value_of(ctx, cfg, "match")
        ctx["value"] = value_of(ctx, cfg, "value")
        answers = query(resolver, ctx["qname"], rec["type"])
        actual = " / ".join(answers)
        shown = cap(actual)  # match per-answer; display a bounded slice of the join
        mode = cfg["value_templates"][rec["type"]].get("match_mode", "contains")
        status = check_answers(expected, answers, mode)
        if status == "ok":
            say(f"  {GREEN}OK{RESET}   {label(rec):<46} {shown}")
            passed += 1
        else:
            say(f"  {RED}FAIL{RESET} {label(rec):<46} "
                  f"{failure_text(mode, status, expected)}")
            say(f"       {'':<46} got: {shown or '<empty>'}")
            failures.append(ctx)
            failed_records.append(rec)

    say(f"\nResult: {passed} passed, {len(failures)} failed.")

    if failures and args.provider:
        say(f"\n{BOLD}How to fix {len(failures)} record(s) in {args.provider}:{RESET}")
        if args.fix_format == "long":
            for ctx in failures:
                say(f"\n• {ctx['type']} {ctx.get('label', ctx['host'])}")
                for line in render_fix(cfg, args.provider, ctx):
                    say(f"  {line}")
        else:
            groups: dict[str, list[dict]] = {}  # group failures by type, in order
            for ctx in failures:
                groups.setdefault(ctx["type"], []).append(ctx)
            for rtype, ctxs in groups.items():
                say()
                for line in render_fix_table(cfg, args.provider, rtype, ctxs):
                    say(line)
    elif failures:
        choices = ", ".join(providers)
        say(f"\nRe-run with --provider ({choices}) to see exactly what to enter.")

    if args.bind_failed_only:
        if failed_records:
            sys.stdout.write(bind_zone(cfg, domain, failed_records, failed_only=True))
        else:
            say("\nNothing failed: there are no records to export.")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
