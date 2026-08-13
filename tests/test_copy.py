#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The web app's paste-ready copy text (issues #15/#16/#17).

"Copy results" and "Copy fix instructions" put Markdown on the clipboard for
pasting into support email and GitHub issues, and each How-to-fix table cell has a
"⧉" that copies just that one panel value. That text is web-only — the CLI
has neither a clipboard nor a URL — so it has no Python twin to compare against
the way tests/test_parity.py does; instead a Node harness
(tests/copy/run_js.mjs) runs the builders in app.js and the expectations live
here. Skips gracefully if `node` is missing.

The rules worth pinning: the internal "UNVERIFIED — confirm the field labels…"
sentence never reaches the clipboard, Markdown tables can't be broken by a cell
value, blank fields say so, DNS-derived text can't smuggle control bytes into
whatever the recipient pastes into, a per-cell copy is exactly the panel value
(never a reader hint appended to it), and every copy ends with a re-check link.

What no test here can cover is the clipboard itself: click the buttons in a real
browser (the section ones flip to "Copied ✓", a cell's "⧉" to "✓").
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
CFG = json.loads((ROOT / "records.json").read_text())
HARNESS = Path(__file__).parent / "copy" / "run_js.mjs"

SITE = "https://thunderbird.github.io/dns-scripts/"
LINK = f"{SITE}?domain=example.com&provider=porkbun"

# publicHeader() rules, on synthetic headers so the test pins the behaviour
# rather than mirroring whatever records.json happens to say today.
PUBLIC_HEADER_CASES = [
    # The caveat is a whole sentence, not just the "UNVERIFIED —" token.
    ("UNVERIFIED — confirm the field labels against your panel. Panel → Add record → MX:",
     "Panel → Add record → MX:"),
    # A parenthetical inside the caveat doesn't end it early.
    ("UNVERIFIED — confirm the labels (SRV form per KB article 109). Panel → SRV:",
     "Panel → SRV:"),
    # Verified providers are passed through untouched.
    ("Namecheap → Advanced DNS → Mail Settings:",
     "Namecheap → Advanced DNS → Mail Settings:"),
    # No sentence break to cut at: drop the token and keep the rest.
    ("UNVERIFIED — no sentence break here", "no sentence break here"),
]

MD_CELL_CASES = [
    ("mail.thundermail.com", "mail.thundermail.com"),
    ("a|b", "a\\|b"),                    # a raw pipe would split the row
    ("", "(leave blank)"),               # e.g. the Host field at the apex
    ("x\ny", "x y"),                     # a newline would end the row
    ("a\u0001b", "a\ufffdb"),  # control bytes never reach a paste
    ("z" * 400, "z" * 300 + "…"),        # same length cap as the on-screen values
]

# copyValue() — what a per-cell "⧉" button puts on the clipboard (issue #17).
# A field template may append an inline hint after a run of spaces; that's for the
# reader, and must not ride along into the provider's panel on a paste.
COPY_VALUE_CASES = [
    ("mail.thundermail.com", "mail.thundermail.com"),
    # namecheap's CNAME Value template: value, then a spaced-out hint.
    ("tm1.example.com.dkim.thunderhosted.com   (no trailing dot)",
     "tm1.example.com.dkim.thunderhosted.com"),
    # Single-spaced values are never split — SRV packs four fields into one.
    ("0 0 443 mail.thundermail.com", "0 0 443 mail.thundermail.com"),
    ("v=spf1 include:spf.thundermail.com -all", "v=spf1 include:spf.thundermail.com -all"),
    # A parenthetical that IS the value (METANET's weight dropdown) survives.
    ("niedrig (0)", "niedrig (0)"),
    ("", ""),                            # e.g. the Host field at the apex
]

SRV_NOTE = " (any weight, lowest priority number)"

RESULTS_ROWS = [
    {"ok": False, "status": "missing", "record": "MX @",
     "expected": "10 mail.thundermail.com", "found": "(nothing)"},
    {"ok": True, "status": "ok", "record": "SRV _jmap._tcp",
     "expected": "0 0 443 mail.thundermail.com" + SRV_NOTE,
     "found": "0 5 443 mail.thundermail.com"},
    # Published, but tied with a competing target (accounts#1163) — its own status
    # word, since "FAIL" would send the reader hunting for a missing record.
    {"ok": False, "status": "conflict", "record": "SRV _imaps._tcp",
     "expected": "0 0 993 mail.thundermail.com" + SRV_NOTE,
     "found": "0 0 993 mail.thundermail.com / 0 0 993 mail.example.net"},
    {"ok": True, "status": "ok", "record": "TXT @ (SPF)",
     "expected": "v=spf1 include:spf.thundermail.com -all (must contain)",
     "found": "v=spf1 include:spf.thundermail.com -all"},
]

FIX_CASES = [
    {"provider": "porkbun", "domain": "example.com", "format": "table",
     "records": [["@", "MX"], ["_jmap._tcp", "SRV"]], "url": LINK},
    {"provider": "namecheap", "domain": "example.com", "format": "long",
     "records": [["tm1._domainkey", "CNAME"]], "url": LINK},
    {"provider": "metanet-plesk", "domain": "example.com", "format": "long",
     "records": [["_jmap._tcp", "SRV"]], "url": LINK},
]


def run_harness() -> dict:
    payload = json.dumps({
        "cfg": CFG,
        "location": SITE,
        "form": {"domain": "example.com", "provider": "porkbun",
                 "resolver": "cloudflare", "fixformat": "table"},
        "publicHeaderCases": [src for src, _ in PUBLIC_HEADER_CASES],
        "providerHeaderCases": [[p, t] for p, block in CFG["providers"].items()
                                for t in block],
        "cellCases": [src for src, _ in MD_CELL_CASES],
        "copyValueCases": [src for src, _ in COPY_VALUE_CASES],
        "fieldCopyCases": [[p, t, "example.com"] for p, block in CFG["providers"].items()
                           for t in block],
        "resultsCase": {"domain": "example.com", "resolver": "cloudflare",
                        "passed": 2, "rows": RESULTS_ROWS, "url": LINK},
        "fixCases": FIX_CASES,
    })
    proc = subprocess.run(["node", str(HARNESS)], input=payload,
                          capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"node harness failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class TestCopyText(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = run_harness()

    # --- the shared re-check link -------------------------------------------

    def test_share_url_is_absolute_and_omits_defaults(self):
        # The link is the bookmarkable URL made absolute: cloudflare/table are
        # the defaults and stay out of it, so the copy reads as short as possible.
        self.assertEqual(self.out["shareUrl"], LINK)

    def test_every_copy_ends_with_the_recheck_link(self):
        for text in [self.out["results"], *self.out["fixes"]]:
            self.assertEqual(text.rstrip().splitlines()[-1], f"Re-check: {LINK}")

    # --- UNVERIFIED stripping (#15) -----------------------------------------

    def test_public_header_rules(self):
        for (src, want), got in zip(PUBLIC_HEADER_CASES, self.out["publicHeaders"]):
            self.assertEqual(got, want, src)

    def test_no_real_provider_header_leaks_the_caveat(self):
        pairs = [(p, t) for p, block in CFG["providers"].items() for t in block]
        for (provider, rtype), got in zip(pairs, self.out["providerHeaders"]):
            with self.subTest(provider=provider, type=rtype):
                original = CFG["providers"][provider][rtype]["header"]
                self.assertNotIn("UNVERIFIED", got)
                self.assertNotIn("confirm the field", got)
                self.assertTrue(got, "header must not be emptied")
                # Only ever a prefix is dropped — the panel instructions survive.
                self.assertTrue(original.endswith(got), got)

    def test_fix_text_never_mentions_unverified(self):
        for text in self.out["fixes"]:
            self.assertNotIn("UNVERIFIED", text)

    # --- Markdown cells ------------------------------------------------------

    def test_md_cell_rules(self):
        for (src, want), got in zip(MD_CELL_CASES, self.out["cells"]):
            self.assertEqual(got, want, repr(src))

    # --- per-cell copy (#17) -------------------------------------------------

    def test_copy_value_rules(self):
        for (src, want), got in zip(COPY_VALUE_CASES, self.out["copyValues"]):
            self.assertEqual(got, want, repr(src))

    def test_no_field_copies_a_reader_hint_into_the_panel(self):
        # Sweep every provider/type: whatever a "⧉" button hands over is a single
        # panel value, so it can't carry the spaced-out hint (or any run of spaces
        # a hint would hide behind) or wrap onto a second line.
        pairs = [(p, t) for p, block in CFG["providers"].items() for t in block]
        for (provider, rtype), fields in zip(pairs, self.out["fieldCopies"]):
            for label, copied in fields:
                with self.subTest(provider=provider, type=rtype, field=label):
                    self.assertNotIn("  ", copied)
                    self.assertNotIn("\n", copied)
                    self.assertEqual(copied, copied.strip())
                    self.assertNotIn("{", copied)  # no unresolved token

    # --- results copy (#16) --------------------------------------------------

    def test_results_markdown(self):
        lines = self.out["results"].splitlines()
        self.assertEqual(lines[0], "**Thundermail DNS check — example.com**")
        self.assertIn("2 passed, 2 failed · resolver: Cloudflare (1.1.1.1)", lines)
        self.assertIn("| Status | Record | Expected | Found |", lines)
        self.assertIn("| --- | --- | --- | --- |", lines)
        self.assertIn("| **FAIL** | MX @ | 10 mail.thundermail.com | (nothing) |", lines)
        self.assertIn(
            f"| OK | SRV _jmap._tcp | 0 0 443 mail.thundermail.com{SRV_NOTE} "
            "| 0 5 443 mail.thundermail.com |", lines)
        self.assertIn(
            f"| **CONFLICT** | SRV _imaps._tcp | 0 0 993 mail.thundermail.com{SRV_NOTE} "
            "| 0 0 993 mail.thundermail.com / 0 0 993 mail.example.net |", lines)
        # One row per record, plus header + separator.
        self.assertEqual(len([l for l in lines if l.startswith("|")]),
                         len(RESULTS_ROWS) + 2)

    # --- fix copy (#15) ------------------------------------------------------

    def test_fix_table_format(self):
        lines = self.out["fixes"][0].splitlines()
        self.assertEqual(lines[0], "**How to fix 2 record(s) in porkbun — example.com**")
        self.assertIn("| Type | Host | Priority | Answer |", lines)
        self.assertIn("| --- | --- | --- | --- |", lines)
        # Porkbun leaves the apex Host empty; an empty cell in an email reads as
        # an omission, so it's spelled out.
        self.assertIn("| MX | (leave blank) | 10 | mail.thundermail.com |", lines)
        self.assertIn("| SRV | _jmap._tcp | 0 | 0 443 mail.thundermail.com |", lines)
        # One table per record type.
        self.assertEqual(lines.count("| --- | --- | --- | --- |"), 2)

    def test_fix_long_format(self):
        text = self.out["fixes"][1]
        lines = text.splitlines()
        self.assertEqual(lines[0], "**How to fix 1 record(s) in namecheap — example.com**")
        self.assertIn("### CNAME tm1._domainkey", lines)
        # The field block is fenced so the alignment survives a GitHub paste.
        self.assertEqual(text.count("```"), 2)
        fenced = text.split("```")[1].splitlines()
        labels = [lbl for lbl, _ in CFG["providers"]["namecheap"]["CNAME"]["fields"]]
        self.assertEqual(len([l for l in fenced if l.strip()]), len(labels))
        for label in labels:
            self.assertTrue(any(l.startswith(f"{label}:") for l in fenced), label)
        # Namecheap's CNAME Target template carries a trailing "(no trailing dot)" hint,
        # so the target is inside the line rather than at the end of it.
        self.assertTrue(any("tm1.example.com.dkim.thunderhosted.com" in l
                            for l in fenced))

    def test_fix_long_format_spells_out_blank_fields(self):
        # METANET's Plesk SRV form leaves Domainname empty at the apex.
        fenced = self.out["fixes"][2].split("```")[1]
        self.assertIn("(leave blank)", fenced)
        self.assertNotIn("UNVERIFIED", self.out["fixes"][2])


if __name__ == "__main__":
    unittest.main()
