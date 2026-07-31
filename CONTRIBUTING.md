# Contributing

> We require all those who participate in this repo to agree and adhere to the
> [Mozilla Community Participation Guidelines](https://www.mozilla.org/about/governance/policies/participation/).

Licensed under [MPL-2.0](LICENSE). **Every source file carries the MPL header**
(Python after the shebang, HTML in an opening comment, JS at the top) — add it to
any new source file. Markdown docs like this one don't need it.

For architecture and testing details, see [`README.md`](README.md) and
[`CLAUDE.md`](CLAUDE.md). The short version: the record set, value templates, and
per-provider remediation strings all live in **`records.json`**, read verbatim by
both front-ends (the `verify_thundermail_dns.py` CLI and the `index.html`/`app.js`
web app), so the two can never drift.

## Adding or fixing a DNS provider

A provider is pure data — no code changes. Add a block under `providers` in
`records.json` and both front-ends pick it up automatically (the CLI `--provider`
choice and the web "Show fixes for" dropdown). Give it one entry per record type
(`MX`, `SRV`, `TXT`, `CNAME`), each with a `header` (the instruction line) and
`fields` (a list of `[label, template]` pairs). Templates interpolate the same
tokens the CLI/JS expose on a record — `{host}`, `{subhost}` (host label, blank at
the apex), `{target}`, `{priority}`, `{weight}`, `{port}`, `{value}`, `{match}`,
`{fqdn}`, `{qname}`, `{domain}`. For panels that split the SRV `_service._protocol`
label into separate fields there are also `{service}` (`_jmap`), `{protocol}`
(`_tcp`), `{bareservice}` / `{bareprotocol}` (the same two **without** the leading
underscore, for Plesk/METANET), `{srvhost}` (whatever remains — `@` at the apex) and
`{srvsubhost}` (the same, but blank at the apex).

If a panel needs something none of those cover, add the token to `resolve_record` in
`verify_thundermail_dns.py` **and** `resolveRecord` in `app.js` (they must stay
identical), then add a case to `tests/fixtures/parity_cases.json` and the tuple in
`tests/test_parity.py` / `tests/parity/run_js.mjs` so the parity test covers it.

### Never write a customer's domain into the repo

Provider work starts from a real domain — a support ticket, a screenshot of that
customer's panel, a live zone to check against. **That domain doesn't go into
`records.json`, the docs, the tests, an issue, or a commit message.** Everything here
is public: the repo, the issue tracker, and `RELEASE_NOTES.html` on GitHub Pages.

Write a **placeholder** instead, named after the provider so the docs keep the
distinction they'd lose if every example were `example.com`:

| Instead of the real domain | Write |
| -------------------------- | ----- |
| the IONOS verify target    | `ionos.example.com` |
| the Porkbun verify target  | `porkbun.example.com` |
| a delegated subdomain zone | `thundermail.metanet.example.com` |

`example.com`/`.net`/`.org` are reserved for exactly this ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)),
so a placeholder can never collide with someone's real domain.

**Traceability comes from the artifact, not the domain.** Cite the **ticket number**
(e.g. "TBPRO ticket 7194") or the internal artifact path, and let that be the pointer
to which domain was used. Two things to watch:

- Cite the ticket *number*, not a folder name verbatim — internal ticket folders often
  encode the domain (`6911_IONOS_DNS_<CUSTOMER>_DOT_COM`), which puts it right back
  in the repo.
- **Don't commit the screenshots.** Keep them in the ticket folder and cite them
  ("SRV form screenshot, ticket 7194"). Redact account/billing/personal chrome as
  above; a record list showing the customer's own zone is fine *in the ticket*, not
  in the repo.

What *is* fine to name: the provider's **nameserver hostnames**
(`ns1.hera.metanet.ch`, `curitiba.ns.porkbun.com`, `kiki.bunny.net`) — they're
infrastructure, they identify nobody, and they're what `--resolver` needs; and
domains we own ourselves, used as CLI examples.

### Verify field conventions against the *actual panel* — not an automated fetch

This is the important one, and it's why this file exists.

**Provider field labels and quirks must be confirmed from the live control panel,
not guessed and not scraped by an automated tool.** Two reasons:

1. **Many provider help sites can't be fetched programmatically.** Cosmotown's
   docs, for example, sit behind Cloudflare's bot challenge and return **HTTP 403**
   to `curl`, `WebFetch`, and headless browsers alike (the Wayback Machine has no
   snapshots either). Don't burn time fighting the challenge.
2. **Docs drift from the UI, and the UI is the source of truth.** For Cosmotown the
   live panel contradicted the docs in ways that mattered: records are grouped into
   per-type sections (so there's *no* "Type" field), the value column is labelled
   `Points to` / `TXT Value` (not "Value"), the root Host is left **blank** (never
   `@`), the CNAME target is stored with a trailing dot automatically, and there's
   **no SRV section at all**. A screenshot caught all of that; the docs alone would
   have led us wrong.

**The ideal artifact packet, in priority order:**

1. **A screenshot of the "add / edit record" form** — the modal or panel where you
   actually type a new record, ideally with the **record-type dropdown expanded**.
   This is the single most valuable thing: the expanded dropdown reveals which
   types the panel supports (that's how we'd have known up front that Cosmotown has
   no SRV option), and the form shows the exact *input* field labels the remediation
   strings must mirror. One example each for MX / SRV / TXT / CNAME is ideal.
2. **A screenshot of the record-list view** with real records (like the one that
   drove the Cosmotown block). Shows column labels and how values are *stored /
   normalized* — trailing dots, auto-added quotes, and whether the root shows as
   blank / `@` / the full domain.
3. **A zone-file / BIND export or bulk-import view**, if the provider offers one —
   disambiguates FQDNs, trailing dots, and TTLs in one shot. Rare, but gold.
4. **The docs as rendered text or a PDF** (Print → Save as PDF), *not* HTML source —
   raw HTML is noisy, and for Cloudflare-protected help sites you'd just be capturing
   the challenge page. Docs are a supplement to the screenshots and are mainly needed
   so you can **cite** them (see the Cosmotown links in `README.md`).
5. **The provider name and docs URL**, for the citation and the header wording.

A screenshot from a real customer's panel is perfect — just **redact** any
account / billing / personal chrome first (the DNS records themselves are fine), and
keep the screenshot in the ticket rather than committing it (see above).
Reading the docs in a real browser is the fallback when a screenshot isn't
available; automated fetches are the last resort and usually the least reliable.

### Before you open a PR

- Run the CLI against a domain and eyeball both fix layouts:
  `--provider <name>` (compact table, default) and `--provider <name> --fix-format long`.
- Serve the web app (`python3 -m http.server 8000`), pick the provider, and confirm
  the same output renders with no console/CSP errors.
- Keep the CLI and web renderers in sync — they intentionally duplicate a tiny
  interpreter over `records.json`. See the regression and headless-testing notes in
  [`CLAUDE.md`](CLAUDE.md#testing).
