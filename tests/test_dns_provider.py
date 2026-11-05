#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""DNS provider detection (issue #31): dns_provider.py and nameservers.json.

The matching itself is also compared against the JS twin in tests/test_parity.py.
This file lints nameservers.json and covers the Python-only pieces: the zone walk,
the report, and the fallback reason that --provider auto prints. No network: the
lookups are replaced by a dict.
"""

import json
import re
import unittest
from pathlib import Path

import dns_provider as dp

ROOT = Path(__file__).parent.parent
CFG = json.loads((ROOT / "records.json").read_text())
TABLE = dp.load_table()

# A suffix label: letters, digits, hyphens, and at most one "*".
_SUFFIX_LABEL = re.compile(r"^[a-z0-9-]*\*?[a-z0-9-]*$")


class TestNameserversJson(unittest.TestCase):
    def test_entries_have_the_required_fields(self):
        for e in TABLE:
            with self.subTest(e.get("key")):
                self.assertTrue(e["key"] and e["name"] and e["suffixes"])
                self.assertLessEqual(set(e), {"key", "name", "fixes", "verified", "suffixes"})

    def test_keys_are_unique(self):
        keys = [e["key"] for e in TABLE]
        self.assertEqual(len(keys), len(set(keys)))

    def test_fixes_point_to_a_records_json_provider(self):
        for e in TABLE:
            if "fixes" in e:
                with self.subTest(e["key"]):
                    self.assertIn(e["fixes"], CFG["providers"])

    def test_every_provider_panel_can_be_detected(self):
        # Every fix block except the catch-all can be reached by --provider auto.
        reachable = {e["fixes"] for e in TABLE if "fixes" in e}
        self.assertEqual(set(CFG["providers"]) - reachable, {"generic"})

    def test_suffixes_are_well_formed_and_unique(self):
        seen = set()
        for e in TABLE:
            for suffix in e["suffixes"]:
                with self.subTest(suffix):
                    labels = suffix.split(".")
                    self.assertGreaterEqual(len(labels), 2)
                    self.assertTrue(all(lbl and _SUFFIX_LABEL.match(lbl) for lbl in labels))
                    self.assertLessEqual(suffix.count("*"), 1)
                    self.assertNotIn(suffix, seen)
                    seen.add(suffix)

    def test_each_suffix_matches_its_own_entry(self):
        # No earlier entry swallows a later one (first match wins).
        for e in TABLE:
            for suffix in e["suffixes"]:
                with self.subTest(suffix):
                    host = "ns1." + suffix.replace("*", "12")
                    self.assertEqual(dp.match_nameserver(host, TABLE)["key"], e["key"])


class TestZoneWalk(unittest.TestCase):
    ZONES = {
        "example.com": ["dns2.registrar-servers.com", "dns1.registrar-servers.com"],
        "sub.example.org": ["ns1.hera.metanet.ch"],
    }

    def find(self, domain):
        return dp.find_nameservers(domain, self.ZONES.get)

    def test_apex(self):
        self.assertEqual(self.find("example.com")[0], "example.com")

    def test_walks_up_from_a_hostname(self):
        zone, hosts = self.find("mail.example.com")
        self.assertEqual(zone, "example.com")
        self.assertEqual(len(hosts), 2)

    def test_stops_at_a_delegated_subdomain_zone(self):
        self.assertEqual(self.find("a.sub.example.org"), ("sub.example.org", ["ns1.hera.metanet.ch"]))

    def test_never_queries_the_tld(self):
        asked = []
        dp.find_nameservers("x.example.net", lambda n: asked.append(n))
        self.assertEqual(asked, ["x.example.net", "example.net"])

    def test_nothing_found(self):
        self.assertEqual(self.find("example.net"), (None, []))


class TestReport(unittest.TestCase):
    def report(self, domain, zone, hosts):
        return dp.report(domain, zone, dp.detect_provider(hosts, TABLE), TABLE)

    def test_known_provider(self):
        self.assertEqual(self.report("example.com", "example.com",
                                     ["dns1.registrar-servers.com", "dns2.registrar-servers.com"]), [
            "DNS provider for example.com: Namecheap",
            "Nameservers:",
            "  dns1.registrar-servers.com  Namecheap",
            "  dns2.registrar-servers.com  Namecheap",
            "Fix steps: uv run verify_thundermail_dns.py example.com --provider namecheap",
        ])

    def test_zone_shown_when_walked_up(self):
        lines = self.report("mail.example.com", "example.com", ["ns01.domaincontrol.com"])
        self.assertIn("Zone: example.com", lines)

    def test_unknown_nameserver(self):
        lines = self.report("example.com", "example.com",
                            ["dns1.registrar-servers.com", "ns1.example.net"])
        self.assertEqual(lines[0], "DNS provider for example.com: Namecheap + unknown")
        self.assertIn("  ns1.example.net             (unknown)", lines)
        self.assertFalse(any(line.startswith("Fix steps") for line in lines))
        self.assertIn("To recognize an unknown nameserver, add its suffix to nameservers.json.",
                      lines)

    def test_provider_without_fix_steps_offers_an_issue(self):
        lines = self.report("example.com", "example.com", ["ns-1.awsdns-01.com"])
        issue = [line for line in lines if "file a GitHub issue" in line]
        self.assertEqual(len(issue), 1)
        url = issue[0].split(": ", 1)[1]
        self.assertTrue(url.startswith(dp.ISSUE_URL + "?title=DNS+provider+request%3A+AWS+Route+53"))
        # The pre-filled issue is public, so it must never carry the domain.
        self.assertNotIn("example.com", url)

    def test_known_provider_offers_no_issue(self):
        lines = self.report("example.com", "example.com", ["ns01.domaincontrol.com"])
        self.assertFalse(any("GitHub issue" in line for line in lines))

    def test_no_nameservers(self):
        self.assertEqual(self.report("example.com", None, []),
                         ["DNS provider for example.com: unknown (no NS records found)"])


class TestFallbackReason(unittest.TestCase):
    def reason(self, hosts):
        result = dp.detect_provider(hosts, TABLE)
        self.assertIsNone(dp.fixes_for(result))
        return dp.fallback_reason(result)

    def test_reasons(self):
        self.assertEqual(self.reason([]), "no NS records found")
        self.assertEqual(self.reason(["ns1.example.net"]),
                         "the nameservers are not in nameservers.json")
        self.assertEqual(self.reason(["dns1.registrar-servers.com", "ns01.domaincontrol.com"]),
                         "the nameservers belong to more than one provider")
        self.assertEqual(self.reason(["dns1.registrar-servers.com", "ns1.example.net"]),
                         "the nameservers belong to more than one provider")
        self.assertEqual(self.reason(["ns-1.awsdns-01.com"]),
                         "there are no fix steps for AWS Route 53 yet")


if __name__ == "__main__":
    unittest.main()
