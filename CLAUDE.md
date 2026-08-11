# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Purpose

`dns-scripts` verifies that a domain's DNS matches the **Thundermail**
(thundermail.com) email setup and, when records are missing/wrong, prints exactly
what to enter in a given DNS provider's control panel. It ships as **two
front-ends over one data file**:

- **CLI** — `verify_thundermail_dns.py` (Python, run via `uv`).
- **Web** — `index.html` + `app.js`, a static page that does all lookups in the
  browser via DNS-over-HTTPS. Hosted on GitHub Pages:
  **https://thunderbird.github.io/dns-scripts/**

The checked set is 13 records: 1 MX, 5 SRV (jmap/caldavs/carddavs/imaps/submission),
4 TXT (SPF / MTA-STS / TLSRPT / DMARC), 3 DKIM CNAMEs.

## Core architecture & crucial decisions

- **Single source of truth = `records.json`.** It holds the record set,
  `value_templates` (how each type's expected/full value string is built), and the
  per-provider remediation strings (`namecheap`, `squarespace`, `cosmotown`,
  `generic`). BOTH
  front-ends read it, so they can never drift. **Add a record or a provider once in
  `records.json` and both the CLI and the web app pick it up** — do not hardcode
  records/strings in the Python or JS.
- **Each front-end keeps only a tiny interpreter** (~20 lines): an `interpolate`
  (`{field}` token substitution), a `resolve_record`/`resolveRecord` (fills
  `{domain}`, computes `qname`/`fqdn`, and `subhost` = the host label but empty at
  the apex, for panels like Cosmotown whose Host field is left blank — not `@` —
  for the root domain), and one platform-specific DNS-query
  function — dnspython (CLI) vs a DoH `fetch` (web). These are intentionally
  duplicated in Python and JS; keep them in sync. The **hostname-validation regex**
  is likewise duplicated in both — keep it identical.
- **SRV-label split tokens (`{service}`/`{protocol}`/`{srvhost}`).** The interpreter
  also splits the SRV host label on `.`: `{service}` = first label (`_jmap`),
  `{protocol}` = second (`_tcp`), `{srvhost}` = the rest or `@` (always `@` for our
  records, which live at the apex). They were added for GoDaddy, whose add-record
  form breaks SRV into separate Service/Protocol/Name fields; other panels keep the
  whole `_jmap._tcp` in one Host field. They're computed for all records but
  only referenced by the split-SRV templates (`godaddy`, `ionos`, `hover`,
  `namecheap`). There's a
  sibling token **`{srvsubhost}`** = the same "rest" label but **blank at the apex
  instead of `@`** (mirroring how `{subhost}` relates to `{host}`); it exists only for
  Hover, whose SRV form leaves the optional Subdomain field empty for the root. Two more
  siblings, **`{bareservice}`/`{bareprotocol}`**, are `{service}`/`{protocol}` with the
  leading underscore stripped (`jmap`/`tcp`) — they exist only for `metanet-plesk`, whose
  Plesk SRV form documents its Service-Name/Protokoll fields as taking the bare name
  ("Beispiel: SIP (ohne Unterstrich)"). Like the
  rest of the interpreter, the split is **duplicated in both Python and JS — keep it
  identical.**
- **SRV weight is deliberately not compared.** `value_templates.SRV.match_mode` is
  `exact_ignore_weight`, not `exact`: `matches()` compares priority/port/target exactly
  (preserving the #10 fix) but accepts any weight, because weight only distributes load
  between competing targets at the same priority and Thundermail publishes one target per
  service — while Plesk/METANET's weight field is a dropdown in steps of 5, making the
  canonical `weight: 1` unenterable. `records.json` still *publishes* weight 1 (it's what
  the fix instructions print for every other provider); only the comparison is relaxed.
  Whether the published value should become `0` is issue #14. The mode lives in
  `matches()`/`srv_fields()` in Python and `matches()`/`srvFields()` in JS — **keep the
  two identical**, and note both front-ends also word the mismatch from a `_VERBS`/`VERBS`
  table keyed by match mode.
- **Interpolation contract (both languages, must match):** substitute `{domain}`
  into every string field first; then `{field}` tokens in templates resolve against
  the concrete record. `re.sub`/`String.replace` use a **function** replacement so
  values are inserted literally (no second pass).
- **Web lookups use public DoH** (Cloudflare `cloudflare-dns.com/dns-query` with
  `accept: application/dns-json`, or Google `dns.google/resolve`). Public resolvers
  cache negative answers, so a freshly-added record can lag; the **CLI can query an
  authoritative NS directly** to bypass: `--resolver dns1.registrar-servers.com`
  (Namecheap). **Check the domain's actual delegation first** (`dig NS <domain>`) —
  Cosmotown, for example, runs two nameserver families: `ns1..ns4.cosmotown.com`
  (Cloudflare-fronted) and `ndns1`/`ndns2.cosmotown.com` (AWS). A domain lives on
  only one; querying the wrong one returns `REFUSED` (shows up as `<empty>` for
  every record). Cosmotown example: `--resolver ndns1.cosmotown.com`
  ([Cosmotown: nameservers](https://cosmotown.zendesk.com/hc/en-us/articles/214830046-How-to-change-your-Nameservers-What-are-Cosmotown-s-Nameservers)).
  Bunny DNS delegates to `kiki.bunny.net` / `coco.bunny.net`, so
  `--resolver kiki.bunny.net` queries it authoritatively (verified against the live
  `bunny.example.com` zone — 13/13).
- **Provider field conventions were verified against each provider's docs, not
  guessed** (e.g. Squarespace uses Name + a separate Priority + `Data` = "weight port
  target"). Provider menu wording may drift — re-verify if a user reports it's off.
  `namecheap`'s SRV row is a case in point: it used to be
  Host/Priority/Weight/Port/Target, and as of a live panel screenshot on 2026-08-11
  (TBPRO ticket 6978) it has **no Host field at all** — the label is split into
  `Service` (`_jmap`) + `Protocol` (`_tcp`), the GoDaddy/IONOS/Hover shape, followed by
  Priority/Weight/Port/Target and a TTL dropdown (issue #18). Namecheap's
  [SRV article](https://www.namecheap.com/support/knowledgebase/article.aspx/9765/2237/how-to-create-a-srv-record-for-a-domain/)
  matches, and notes a *subdomain* is appended to the Protocol field (`_tcp.mc`)
  rather than typed into a host box — irrelevant for us, since all 13 records are at
  the apex, so plain `{protocol}` is right. MX/TXT/CNAME rows are unchanged.
  `cosmotown` was verified against a live panel (cosmotown.example.com). Its quirks:
  records are grouped into per-type sections each with its own `+ Quick Add`
  (so there's no Type field); columns are `Priority`/`Host`/`Points to` (MX),
  `Host`/`Points to` (CNAME), `Host`/`TXT Value` (TXT); MX Host is left blank for
  the root and the panel auto-fills the domain; the CNAME `Points to` is stored
  with a trailing dot automatically; TXT values are wrapped in quotes by the panel
  and are case-sensitive; and **there is no SRV section at all** — the SRV block
  routes the user to Cosmotown support instead. Docs:
  [changing/saving DNS records](https://cosmotown.zendesk.com/hc/en-us/articles/214829926-How-to-change-and-save-your-DNS-Records),
  [adding a host name](https://cosmotown.zendesk.com/hc/en-us/articles/214830006-How-to-add-a-Host-Name-to-your-Domain-name-s-DNS),
  [updating the MX record](https://cosmotown.zendesk.com/hc/en-us/articles/214830106-How-to-update-the-MX-Record)
  (Zendesk is behind Cloudflare, so these need a real browser — automated fetches 403).
  `bunny` was verified against bunny.net's
  [DNS records docs](https://docs.bunny.net/docs/dns-records). Its add-record dialog
  is a single form (`Hostname`/`Type`/`TTL`/`Value`, Type chosen from a dropdown):
  `Hostname` is left **empty** for the root (never `@`), and there is **one `Value`
  field with no separate Priority/Weight/Port**, so MX and SRV put the whole record
  string in `Value` (the `{match}` template — e.g. `10 mail.thundermail.com`). The
  record list's `Weight` column is bunny's A/AAAA load-balancing "Routing Weight",
  not the SRV weight, so it's irrelevant here.
  `godaddy` (**UNVERIFIED** — from GoDaddy's help docs + a screenshot of the live SRV
  add-form, not yet confirmed end-to-end; headers carry an `UNVERIFIED —` prefix, drop
  them once validated on a live GoDaddy-hosted domain). A single Add-record form with a
  Type dropdown (like bunny). Apex `Name` is written as **`@`** (`{host}`), *not* blank
  like bunny/cosmotown. MX has a separate `Priority`; SPF is a plain `TXT`. The
  distinctive quirk: the **SRV form splits the record into separate `Service`
  (`_jmap`) + `Protocol` (`_tcp`) + `Name` (`@`) fields** — the reason the
  `{service}`/`{protocol}`/`{srvhost}` tokens exist. Note this is a *UI-layout*
  difference only: contrast Spaceship, whose *import preview* also displayed a split
  but whose API stores SRV as one combined `name` (`_jmap._tcp`) — so `spaceship` ships
  the combined form and only `godaddy` splits it. Docs: GoDaddy Help CA articles for
  [MX](https://www.godaddy.com/en-ca/help/add-an-mx-record-19234),
  [TXT](https://www.godaddy.com/en-ca/help/add-a-txt-record-19232),
  [SPF](https://www.godaddy.com/en-ca/help/add-an-spf-record-19218),
  [CNAME](https://www.godaddy.com/en-ca/help/add-a-cname-record-19236),
  [SRV](https://www.godaddy.com/en-ca/help/add-an-srv-record-19216).
  `hover` (**UNVERIFIED** — the SRV field layout is confirmed from a screenshot of the
  live *Edit DNS Record* form; MX/TXT/CNAME field labels come from Hover's
  [Managing DNS Records at Hover](https://support.hover.com/) docs, not a live add-record
  screenshot; drop the `UNVERIFIED —` prefixes once confirmed end-to-end — `hover.example.com`
  is the verify target, hosted on `ns1`/`ns2.hover.com`). A single **Add a record** form
  with a Type dropdown (like bunny/godaddy). MX and TXT write the apex host as **`@`**
  (`{host}`, per Hover's docs). The distinctive quirk: like GoDaddy/IONOS, the **SRV form
  splits the label into separate `Service` (`_jmap`) + `Protocol` (`_tcp`) fields** — but
  its optional `Subdomain` field is left **blank** for the apex (`{srvsubhost}`, *not*
  `@`; the panel shows your domain beside the empty box). MX uses `Mail Server` for the
  target, TXT uses `Content`, CNAME uses `Target Name` (no trailing dot); Hover can't set
  a CNAME on the root, but every DKIM CNAME is on a subdomain so that's a non-issue.
  `digitalocean` (**UNVERIFIED** — the **SRV** field layout is confirmed from a screenshot
  of the live *Create a record* dialog; MX/TXT/CNAME labels come from DigitalOcean's
  [manage-records docs](https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/),
  not a live add-record screenshot; drop the `UNVERIFIED —` prefixes once confirmed
  end-to-end — `digitalocean.example.com` is the verify target, hosted on `ns1`/`ns2`/`ns3.digitalocean.com`).
  A single **Create a record** dialog with a Record Type dropdown (like bunny/godaddy/hover).
  Apex host is **`@`** (`{host}`) for MX/TXT, *not* blank. Unlike GoDaddy/IONOS/Hover it
  keeps the whole `_service._protocol` label in **one** `Hostname` field — so SRV uses
  `{host}`, not the split `{service}`/`{protocol}` tokens. The distinctive quirk: **any
  target entered without a trailing dot gets your domain appended** (the SRV *Will direct
  to* doc spells this out), so MX/SRV/CNAME targets are emitted as `{target}.` with the dot
  (like `ovh`). This is confirmed live: `digitalocean.example.com`'s SRV targets were entered without the
  dot and resolve as `mail.thundermail.com.digitalocean.example.com` — so its five SRV records are actually
  broken (and, separately, the substring-match checker falsely reports them OK — see the
  matching bug). MX field is `Mail provider's mail server`, TXT is `TXT Value`, CNAME is
  `Is an alias of`; SPF/DKIM are plain TXT per the docs (DKIM here is a CNAME).
  `porkbun` (**UNVERIFIED** — MX/TXT/CNAME field layout from Porkbun's KB
  [article 231](https://kb.porkbun.com/article/231-how-to-add-dns-records-on-porkbun)
  and SRV from [article 109](https://kb.porkbun.com/article/109-how-to-create-an-srv-record)
  (screenshots), not confirmed end-to-end on a live panel; drop the `UNVERIFIED —` prefixes
  once confirmed — `porkbun.example.com` is the verify target, hosted on
  `curitiba`/`fortaleza`/`maceio`/`salvador.ns.porkbun.com`, so
  `--resolver curitiba.ns.porkbun.com` queries it authoritatively). A single **Add Record**
  dialog with a Type dropdown (like bunny/godaddy/hover/digitalocean); Porkbun DNS is
  Cloudflare-backed. Apex host is left **blank** (`{subhost}`), *not* `@` — the
  bunny/cosmotown/ovh pattern. Like DigitalOcean it keeps the whole `_service._protocol`
  label in **one** `Host` field (SRV uses `{host}`, not the split tokens). MX and SRV show a
  separate **Priority** field, and the SRV **Answer** field packs Weight/Port/Target on one
  line (`{value}`, the squarespace-style split). Unlike `ovh`/`digitalocean`, targets are
  stored **verbatim with no trailing dot** — confirmed live on `porkbun.example.com` (its MX and
  DKIM CNAME targets came back unappended), so MX/SRV/CNAME emit plain `{target}` like
  `bunny`. Value field is labelled contextually in the UI (`IPv4 Address`/`Target`/`Answer`);
  we emit `Answer` for MX/SRV/TXT and `Target` for CNAME. SPF/DKIM are plain TXT (DKIM is a
  CNAME here).
  `metanet-plesk` (**partly UNVERIFIED** — the SRV field layout is confirmed from a screenshot
  of the live *Ressourceneintrag bearbeiten* form on `thundermail.metanet.example.com`, and the TXT
  form + auto-quoting from METANET's own docs; the German **MX/CNAME** labels
  (`Mail-Exchange-Server`, `Kanonischer Name`) are stock-Plesk guesses, so those three headers
  keep the `UNVERIFIED —` prefix while TXT ships without one). METANET's **Plesk** panel —
  the first Plesk-based *and* first German-language provider; field labels are emitted in
  **German with an English gloss** (`Zielhost (Target host)`) since that's what the user sees.
  A single **Eintrag hinzufügen** form with an `Eintragstyp` dropdown (NS/A/AAAA/CNAME/MX/PTR/
  TXT/SRV/DS/CAA), reached via *Websites & Domains → DNS-Einstellungen*. Apex `Domainname` is
  left **blank** (`{subhost}`), never `@` — the bunny/cosmotown/ovh/porkbun pattern. Quirks:
  the SRV form **splits Service-Name/Protokoll and wants them without the leading underscore**
  (the reason `{bareservice}`/`{bareprotocol}` exist; its `Domainname` reuses `{srvsubhost}`);
  **`Priorität` and `Relative Gewichtung` are dropdowns**, and the weight one only offers
  0/5/10…50 so `weight: 1` can't be entered — the SRV block emits the literal `niedrig (0)`
  and the checker ignores weight (see the `exact_ignore_weight` note above, issues #13/#14);
  Weight/Port/Target are three separate fields (`Relative Gewichtung`/`Zielport`/`Zielhost`),
  so SRV uses the individual tokens like namecheap/hover, not `{value}`; targets are stored
  **verbatim with no trailing dot** (Plesk adds the root dot itself — confirmed live, unlike
  ovh/digitalocean); **TXT values are auto-quoted by the panel** so they're emitted unquoted
  (like cosmotown, field `TXT-Eintrag`); and **nothing goes live until `Aktualisieren`
  (Update) is clicked** on the pending-changes banner, which all four headers state. The
  headers also point at METANET's paid *Premium Service: Individuelle DNS-Einstellungen*
  (`support@metanet.ch`) as an optional hand-off — unlike cosmotown, every type is
  self-serviceable here. Key is `metanet-plesk` (not `plesk`) because only METANET's build was
  confirmed; generalise if another Plesk host appears. Verify target
  `thundermail.metanet.example.com` (a delegated *subdomain* zone on `ns1`/`ns2.hera.metanet.ch`, so
  `--resolver ns1.hera.metanet.ch`); it sits at 12/13, with only a misconfigured
  `_imaps._tcp` target outstanding. Docs:
  [METANET: Plesk DNS-Verwaltung](https://www.metanet.ch/de/support/dns-nameserver/dns/plesk-dns-verwaltung)
  (German; a Firefox-translated PDF and the SRV screenshot live in the ticket folder
  `THUNDERBIRD_2023/TBPRO/7194_METANET_PLESK/`).
- **Bookmarkable web URLs (web-only).** `app.js` mirrors the form state (domain /
  provider / resolver / fixformat) into the query string via `history.replaceState`,
  and on load repopulates the fields and auto-runs when a `domain` is present.
  Untrusted params are validated against the known option sets before use and only
  ever assigned to `input.value`/`select.value` (never `innerHTML`); the domain still
  passes the hostname regex before any lookup — so it adds no XSS surface and needs
  **no CSP change**.
- **Copy-to-clipboard buttons (web-only).** Each of the two output sections has one:
  *Copy results* (`#resultsactions`, after every completed check) and *Copy fix
  instructions* (inside `#fixes`, only when a provider is picked and something
  failed). Both put **Markdown** on the clipboard — tables survive a paste into a
  GitHub issue and still read as plain text in email — and both append
  `Re-check: <absolute bookmarkable URL>` from `shareUrl()`, the absolute twin of
  `updateUrl()` (they share `stateParams()`). Two rules matter: the text is built
  from the check's **data**, never scraped out of the DOM, and `publicHeader()`
  strips the internal `UNVERIFIED — confirm the field labels…` *sentence* (not just
  the token) from provider headers, since that's a note to us, not to the domain
  owner receiving the instructions — the on-screen copy still shows it. DNS-derived
  text goes through `clean()` (control bytes → `U+FFFD`, same `MAX_VALUE` cap as the
  UI) because a paste can land in a terminal, and `mdCell()` escapes `|` and spells
  empty fields as `(leave blank)`. `writeClipboard()` prefers
  `navigator.clipboard.writeText` and falls back to a throwaway `<textarea>` +
  `execCommand("copy")` for non-secure contexts (`file://`). No inline script and no
  `innerHTML`, so **no CSP change**.
- **Per-cell `⧉` copy in the fix table (web-only, issue #17).** Every cell of the
  compact How-to-fix table carries a small `⧉` button that copies **just that one
  panel value** — the field-by-field job the user is actually doing with their
  provider's panel open in the next tab, as opposed to *Copy fix instructions*, which
  copies the whole block as Markdown for an email or issue. Built in `fixCell()`
  (called by `fixTable()`); `copyButton()` takes an options object so the cells can
  pass the compact glyph pair (`⧉` → `✓`, `✗` on failure — "Copied ✓" doesn't fit in a
  column) plus an `aria-label`/`title` (`Copy Host: _jmap._tcp`), since a bare glyph is
  not a label. The buttons are always visible (dim until hover/focus) rather than
  hover-revealed, so they work on touch. Two wrinkles: **(a)** a field template may
  append a **reader hint after a run of two-plus spaces** (`namecheap` CNAME `Value` =
  `{value}   (no trailing dot)`) — that's guidance, not something to paste into a
  panel, so `copyValue()` cuts the string at the first 2+-space run and the cell
  renders the remainder as a muted `.cellhint` span. Keep that spacing convention if
  you add a hint to a template (single-spaced values like SRV `0 1 443 host` are
  untouched, and `tests/test_copy.py` sweeps every provider field to prove no copy
  carries a hint). **(b)** A **blank** value (apex host on
  bunny/cosmotown/ovh/porkbun/metanet-plesk) shows an italic `(leave blank)` and gets
  **no** button — nothing to paste, and a copy of `""` can only ever look like it
  failed. Values come from `interpolate(tpl, ctx)`, never scraped from the DOM;
  `textContent` only, so again **no CSP change**.
- Those three features are the **intentionally web-only ones** — the CLI has no URL
  and no clipboard, so the Python/JS-in-sync rule does not apply to them.

## Security posture

Reviewed; no exploitable injection/XSS/RCE. Defense-in-depth already in place —
preserve it when editing:

- **Web renders only via `textContent`** (never `innerHTML`) and builds DoH URLs
  with `encodeURIComponent`. A **CSP `<meta>`** locks `script-src 'self'` and
  `connect-src` to the two DoH hosts + self. Don't introduce inline scripts,
  `eval`, or `innerHTML` (they'd need CSP changes and reopen XSS). URL query params
  (the bookmarkable-state feature) are untrusted input — validate against known
  option sets and assign only to `input.value`/`select.value`, never `innerHTML`.
- **CLI** escapes control/terminal bytes from DNS-derived output (`sanitize`),
  validates the domain against a hostname regex before any lookup (exit 2 on
  invalid), and caps displayed answer length.
- `--resolver` / `DNS_RESOLVER` are trusted (operator-controlled), out of scope.

## Customer domains never enter the repo

Provider work starts from a real customer domain (ticket, panel screenshot, live zone
to check against), but **that domain goes nowhere persistent or public** — not
`records.json`, the docs, the tests, an issue, a commit message, or a memory file.
Repo, issue tracker and `RELEASE_NOTES.html`-on-Pages are all public. Use a
provider-named placeholder (`ionos.example.com`, `porkbun.example.com`,
`thundermail.metanet.example.com` — RFC 2606 reserves `example.*`, so it can't collide
with a real domain), which also keeps per-provider verify targets distinguishable in
the docs. **Traceability lives in the artifact:** cite the TBPRO ticket *number* (not
the folder name — those often encode the domain, e.g.
`6911_IONOS_DNS_<CUSTOMER>_DOT_COM`) or the screenshot in that folder, and don't commit
the screenshots. Provider **nameserver** hostnames (`ns1.hera.metanet.ch`,
`curitiba.ns.porkbun.com`) are fine — infrastructure, and what `--resolver` needs — as
are domains we own (`glamrocnamecheap.com` is the CLI-example/regression domain). The
contributor-facing version of this rule is in
[`CONTRIBUTING.md`](CONTRIBUTING.md#never-write-a-customers-domain-into-the-repo).
Scrubbed repo-wide (files, issues, and history) on 2026-07-30.

## Commands

```sh
uv sync                                   # one-time / after dep changes

# CLI
uv run verify_thundermail_dns.py <domain>
uv run verify_thundermail_dns.py glamrocnamecheap.com --provider namecheap
uv run verify_thundermail_dns.py <domain> --resolver dns1.registrar-servers.com

# Web (static — any file server)
python3 -m http.server 8000               # then open http://localhost:8000/
```

Exit status is `0` only when all 13 records are present and correct.

## Testing

- **Automated suite (`tests/`, stdlib `unittest`, no network):** run with
  `uv run python -m unittest discover -s tests -t . -v` (also runs in CI via
  `.github/workflows/test.yml` on push/PR). `test_verify.py` covers the pure
  interpreter (matching incl. the #10 exact-vs-contains regression, token
  resolution, provider rendering) and lints `records.json` (every provider covers
  all four types; every field template interpolates with no unknown/leftover
  token; each `value_templates.<TYPE>` has a valid `match_mode`). `test_parity.py`
  enforces the **Python↔JS sync rule**: it runs `tests/fixtures/parity_cases.json`
  through both the Python functions and a Node harness (`tests/parity/run_js.mjs`,
  which loads `app.js` in a `vm` sandbox) and asserts identical results — so when
  you change the interpreter in one language, update the other or this test fails.
  Add a fixture case whenever you add an interpreter token or `match_mode`.
  `test_copy.py` covers the web-only clipboard text (see the copy-button bullet
  below). ⚠️ **Harness fragility (by design):** both Node harnesses rely on
  `app.js`'s *only* top-level side effect being the trailing
  `loadConfig().then(...)`, which they neutralize by stubbing `fetch` to stay
  pending (so the DOM-touching callback never fires). If you add **new top-level
  (module-load-time) code to `app.js`** that touches `document`/`window`/`location`/
  etc., the sandbox stubs in *both* `tests/parity/run_js.mjs` and
  `tests/copy/run_js.mjs` must be extended to match, or those tests error at load.
  This is intentional pressure to keep `app.js`'s pure functions free of
  load-time DOM coupling — but it means "just added a line to app.js" can surface
  as a harness failure rather than an obvious app bug; check the stubs first in
  that case.
- **CLI regression:** normal-input output should stay byte-identical across
  refactors. Capture `glamrocnamecheap.com` (expect 13/13, exit 0) and
  `example.com --provider namecheap|squarespace|cosmotown|generic` before a change, then
  `diff` after. Also test invalid/malicious domains → rejected with exit 2.
- **Fix layout:** `--provider` fixes default to a compact per-type table (one
  column per provider field, one row per failing record); `--fix-format long`
  gives the older one-labelled-block-per-record layout. The web app mirrors this
  with the "Fix format" selector (Table/Detailed). Both are driven off the same
  `providers.<name>.<TYPE>.fields` in `records.json` — keep the two renderers in
  sync. When capturing a CLI baseline, pin `--fix-format` so the diff is stable.
- **Web headless (Playwright):** this repo has no Playwright dependency; run it
  from an env that does. Serve the site, then drive it. **The CSP (`script-src
  'self'`, no `unsafe-eval`) blocks Playwright's `page.wait_for_function`** — poll
  `page.inner_text('#summary')` in a loop instead. Confirm no console errors and no
  CSP violations (that verifies DoH + `records.json` requests aren't blocked).
- **Copy buttons:** the text builders are covered by `test_copy.py` + its own Node
  harness `tests/copy/run_js.mjs` (same sandbox trick as the parity one, but it also
  needs `URL` and a real `location.href` for `shareUrl()`, and form fields with
  values for `stateParams()`). One wrinkle: only `function` declarations land on the
  vm's global — `const` arrows like `mdCell` don't, so the harness appends a
  `globalThis.__copy = { mdCell, copyValue }` epilogue to the *same* script rather than
  adding test hooks to `app.js`. The per-cell buttons (#17) are covered the same way —
  through the pure `copyValue()`, plus a sweep of every provider field asserting no
  copied value carries a reader hint; the DOM assembly in `fixCell()` is not covered
  (the harness's `createElement` returns one shared stub), so check the table in a
  browser. What it can't cover is the clipboard itself: click the
  button in a browser (`button.copy` flips to `Copied ✓`, a cell's `⧉` to `✓`). Don't try to read it back
  with `navigator.clipboard.readText()` in a driven browser — it hangs on the
  permission prompt; assert on the button state instead.

## Deployment

GitHub Pages, source = `main` branch root, at
`https://thunderbird.github.io/dns-scripts/`. GitHub Pages can't set HTTP headers,
so the CSP is delivered as a `<meta http-equiv>` tag in `index.html`.

## License & contribution

MPL-2.0. **All source files carry the MPL header** (Python after the shebang, HTML
in an opening comment, JS at the top) — add it to every new file. Contributors
follow the [Mozilla Community Participation Guidelines](https://www.mozilla.org/about/governance/policies/participation/).
