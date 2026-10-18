> We require all those who participate in this repo to agree and adhere to the
> [Mozilla Community Participation Guidelines](https://www.mozilla.org/about/governance/policies/participation/).

# dns-scripts

Small utilities for checking DNS records.

Licensed under [MPL-2.0](LICENSE). Contributing (especially **adding a DNS
provider**)? See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Thundermail DNS checker — web version

**<https://thunderbird.github.io/dns-scripts/>**

The same checks as the `verify_thundermail_dns.py` CLI below, but from a web
browser: enter a domain, optionally pick your DNS provider, and get pass/fail per
record plus exactly what to enter for any that are missing. All lookups run
client-side via DNS-over-HTTPS (Cloudflare or Google) — no server, nothing stored.
Pick **bind (zone file)** in "Show fixes for" to get the records as a BIND zone file
instead, with buttons to copy or download it (see
[Exporting a BIND zone file](#exporting-a-bind-zone-file)).

Run it locally with any static file server:

```sh
python3 -m http.server 8000   # then open http://localhost:8000/
```

> **Single source of truth:** the record set, value templates, and per-provider
> remediation strings live in [`records.json`](records.json), which is read by
> *both* the CLI and the web page (`index.html` + `app.js`). Add a record or a
> provider there once and both front-ends pick it up.

## Setup

Managed with [`uv`](https://docs.astral.sh/uv/):

```sh
uv sync
```

## verify_thundermail_dns.py

Verifies that a domain's DNS is configured for [Thundermail](https://thundermail.com):
the MX record, the JMAP/CalDAV/CardDAV/IMAPS/submission SRV records, the SPF /
MTA-STS / TLSRPT / DMARC TXT records, and the three DKIM CNAMEs.

```sh
uv run verify_thundermail_dns.py glamrocnamecheap.com
```

Exit status is `0` only when every expected record is present and correct, so it's
safe to use in scripts or CI. **SRV is the one type checked relationally rather than
against a literal.** Port and target must match exactly, but the **weight is not
compared at all** (it only distributes load between competing targets at the same
priority, and Thundermail publishes a single target per service — while some panels,
e.g. Plesk / METANET, offer only a fixed dropdown of weights in steps of 5), and the
**priority only has to be a lower number than any other target at that name**. So a
working setup at priority `10` passes, and a record that's published but *tied with or
out-ranked by* a competing target is reported as a **conflict** — it exists, but it may
not win. The recommended values are `priority 0`, `weight 0` (both the lowest). See
[#14](https://github.com/thunderbird/dns-scripts/issues/14) and
[thunderbird-accounts#1163](https://github.com/thunderbird/thunderbird-accounts/issues/1163).
It queries `1.1.1.1` by default (override with
`--resolver` or the `DNS_RESOLVER` environment variable) to avoid stale local
caches. The resolver accepts an IP address or a hostname — e.g. point it at an
authoritative nameserver to bypass public-resolver caching entirely:

```sh
uv run verify_thundermail_dns.py glamrocnamecheap.com --resolver dns1.registrar-servers.com
```

Point it at whichever nameserver is actually authoritative for the domain — check
with `dig NS <domain>` first, since a registrar may run several nameserver sets and
querying the wrong one just returns empty answers. For example, a domain hosted on
Cosmotown's DNS is usually delegated to `ndns1.cosmotown.com` / `ndns2.cosmotown.com`
([Cosmotown: What are Cosmotown's nameservers?](https://cosmotown.zendesk.com/hc/en-us/articles/214830046-How-to-change-your-Nameservers-What-are-Cosmotown-s-Nameservers)):

```sh
uv run verify_thundermail_dns.py <domain> --resolver ndns1.cosmotown.com
```

A domain hosted on Bunny DNS is delegated to `kiki.bunny.net` / `coco.bunny.net`
([bunny.net: DNS records](https://docs.bunny.net/docs/dns-records)):

```sh
uv run verify_thundermail_dns.py <domain> --resolver kiki.bunny.net
```

### Fixing failures

Pass `--provider` to print, for each failing record, what to enter in that DNS
provider's control panel. The output uses the provider's own field names and
follows its quirks, for example how to write the root domain in the Host field.

```sh
uv run verify_thundermail_dns.py glamrocnamecheap.com --provider namecheap
```

For example, a missing DKIM CNAME prints:

```
• CNAME tm1._domainkey
  Namecheap → Advanced DNS → Add New Record → CNAME Record:
      Host:   tm1._domainkey
      Target: tm1.glamrocnamecheap.com.dkim.thunderhosted.com   (no trailing dot)
```

The table shows the main differences between the supported providers. "Root host"
is what you put in the Host or Name field for the root domain. "SRV label" tells
you if the panel keeps `_jmap._tcp` in one field or splits it into Service and
Protocol fields. "Trailing dot" tells you if targets must end with a `.`.

| `--provider`    | Root host | SRV label                  | Trailing dot | Verified |
| --------------- | --------- | -------------------------- | ------------ | -------- |
| `namecheap`     | `@`       | split                      | no           | yes      |
| `squarespace`   | `@`       | one field                  | no           | yes      |
| `cosmotown`     | blank     | no SRV form (ask support)  | no           | yes      |
| `bunny`         | blank     | one field                  | no           | yes      |
| `spaceship`     | `@`       | one field                  | no           | no       |
| `godaddy`       | `@`       | split                      | no           | no       |
| `ionos`         | `@`       | split                      | no           | no       |
| `ovh`           | blank     | one field                  | yes          | no       |
| `hover`         | `@`       | split                      | no           | no       |
| `digitalocean`  | `@`       | one field                  | yes          | no       |
| `porkbun`       | blank     | one field                  | no           | no       |
| `metanet-plesk` | blank     | split, no underscore       | no           | TXT only |
| `cloudflare`    | `@`       | one field                  | no           | yes      |
| `generic`       | full name | full name                  | no           | n/a      |

"Verified" means that a person compared the field names with the live panel or
with the provider's own documentation. The output for an unverified provider starts
each block with `UNVERIFIED —`, so compare the field names with your panel. The
[release notes](RELEASE_NOTES.md) record how each provider was checked.

Provider notes:

- `namecheap`: The MX record goes in *Mail Settings → Custom MX*. The SRV form has
  no Host field.
- `squarespace`: SRV has a separate Priority field. The Data field holds
  `weight port target` on one line.
- `cosmotown`: The panel has no SRV section, so you cannot add the five SRV records
  yourself. The output tells you to ask Cosmotown support. The panel adds quotes to
  TXT values, so enter them without quotes. See Cosmotown's docs for
  [changing and saving DNS records](https://cosmotown.zendesk.com/hc/en-us/articles/214829926-How-to-change-and-save-your-DNS-Records),
  [adding a host name](https://cosmotown.zendesk.com/hc/en-us/articles/214830006-How-to-add-a-Host-Name-to-your-Domain-name-s-DNS),
  and [updating the MX record](https://cosmotown.zendesk.com/hc/en-us/articles/214830106-How-to-update-the-MX-Record).
- `bunny`: The form has one Value field and no Priority, Weight or Port fields. For
  MX and SRV, the whole record goes in Value, for example `10 mail.thundermail.com`
  ([bunny.net: DNS records](https://docs.bunny.net/docs/dns-records)).
- `godaddy`, `ionos`, `hover`: The SRV form splits the label into Service (`_jmap`)
  and Protocol (`_tcp`). IONOS shows Protocol as a dropdown, so pick `TCP`. Hover
  leaves its Subdomain field blank for the root
  ([Hover: Managing DNS Records](https://support.hover.com/support/solutions/articles/)).
- `ovh`, `digitalocean`: If a target has no trailing dot, the panel adds your
  domain to it. `mail.thundermail.com` then becomes
  `mail.thundermail.com.example.com`. The output adds the dot for you
  ([DigitalOcean: manage DNS records](https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/)).
- `porkbun`: MX and SRV have a separate Priority field. The SRV Answer field holds
  `weight port target` on one line
  ([Porkbun: add DNS records](https://kb.porkbun.com/article/231-how-to-add-dns-records-on-porkbun),
  [Porkbun: SRV records](https://kb.porkbun.com/article/109-how-to-create-an-srv-record)).
- `metanet-plesk`: This is [METANET](https://www.metanet.ch/)'s Plesk panel, in
  German. The output shows the German field names with an English translation,
  for example `Zielhost (Target host)`. Enter the SRV service and protocol without
  the underscore (`imaps`, `tcp`). Weight is a dropdown, so pick `niedrig (0)`
  ([#14](https://github.com/thunderbird/dns-scripts/issues/14)). The panel adds
  quotes to TXT values, so enter them without quotes. Nothing goes live until you
  click **Aktualisieren** (Update). METANET also sells a paid service where support
  enters the records for you
  ([METANET: Plesk DNS-Verwaltung](https://www.metanet.ch/de/support/dns-nameserver/dns/plesk-dns-verwaltung)).
- `cloudflare`: Enter TXT values with the double quotes, because Cloudflare does
  not add them. Set **Proxy status** to *DNS only* on the three DKIM CNAMEs. The
  default, *Proxied*, breaks DKIM. Each zone has its own nameservers, so run
  `dig NS <domain>` before you use `--resolver <name>.ns.cloudflare.com`
  ([Cloudflare: create DNS records](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/)).
- `generic`: This prints the full record name and value for any panel.

### Exporting a BIND zone file

A BIND zone file is the standard text format for DNS records (RFC 1035). Many DNS
panels can import one, and you can paste it into a self-hosted zone. `--bind`
prints all 13 Thundermail records in that format and exits. It does no DNS lookups,
so it works offline:

```sh
uv run verify_thundermail_dns.py example.com --bind > example.com.thundermail.zone
```

The output is a fragment, not a full zone: it has `$ORIGIN` but no `SOA`, `NS` or
`$TTL`, so the importing zone's default TTL applies.

> **Warning:** if the zone already has an MX record or an SPF (`v=spf1`) TXT record,
> replace it instead of adding a second one. Many panels add imported records as
> duplicates. Two SPF records make SPF fail, and a second MX record changes where
> mail goes.

To export only the records that failed the check, use `--bind-failed-only`. It runs
the normal check first and writes the check report to stderr, so stdout holds only
the zone file. If nothing failed, it says so and writes no records. The exit status
is the same as for a normal check.

```sh
uv run verify_thundermail_dns.py example.com --bind-failed-only > missing.zone
```

The web version has the same export: pick **bind (zone file)** in "Show fixes for".
It shows all 13 records with **Copy BIND records** and **Download BIND file**
buttons, and an **Only failed records** checkbox. The CLI and the web app produce
byte-identical text.

### Example

```
Verifying Thundermail DNS for glamrocnamecheap.com (resolver 1.1.1.1)

MX:
  OK   @                                              10 mail.thundermail.com
SRV:
  OK   _jmap._tcp                                     0 0 443 mail.thundermail.com
  ...

Result: 13 passed, 0 failed.
```
