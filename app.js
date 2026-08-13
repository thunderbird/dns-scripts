// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Browser twin of the logic in verify_thundermail_dns.py. Both front-ends read
// the same records.json, so the record set, value templates, and provider
// remediation strings live in exactly one place.

const TOKEN = /\{(\w+)\}/g;

// Hostname validation (kept in sync with the same regex in verify_thundermail_dns.py).
const HOSTNAME = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;

// How to word a mismatch, per match_mode (kept in sync with the CLI).
const VERBS = {
  exact: "expected",
  srv_lowest_priority: "expected (any weight, lowest priority number)",
};

// Wording for the "conflict" status: the record is published, but another target at
// the same name can outrank it. Mirrors thunderbird-accounts#1163. (In sync with the CLI.)
const CONFLICT =
  "conflicts: another target here has an equal or lower priority number — " +
  "give the Thundermail target the lowest number (any weight is fine)";

// The same relaxation, as a suffix for the "Expected" column of the copied
// results table (web-only; the CLI has no clipboard).
const MATCH_NOTES = { exact: "", srv_lowest_priority: " (any weight, lowest priority number)" };

const MAX_VALUE = 300; // cap displayed answer length to avoid DOM bloat
const cap = (s) => (s.length <= MAX_VALUE ? s : s.slice(0, MAX_VALUE) + "…");

// Numeric DNS type codes, to keep only answers of the requested type (a DoH
// response can also carry CNAMEs from a resolution chain).
const TYPE_NUM = { A: 1, CNAME: 5, MX: 15, TXT: 16, SRV: 33 };

const RESOLVERS = {
  cloudflare: {
    label: "Cloudflare (1.1.1.1)",
    url: (name, type) =>
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    headers: { accept: "application/dns-json" },
  },
  google: {
    label: "Google (8.8.8.8)",
    url: (name, type) =>
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
    headers: {},
  },
};

// --- shared interpretation of records.json (mirrors the Python helpers) -------

function labelOf(rec) {
  return rec.label ?? rec.host;
}

function resolveRecord(rec, domain) {
  const host = rec.host;
  const ctx = {};
  for (const [k, v] of Object.entries(rec)) {
    ctx[k] = typeof v === "string" ? v.replaceAll("{domain}", domain) : v;
  }
  ctx.domain = domain;
  ctx.qname = host === "@" ? domain : `${host}.${domain}`;
  ctx.fqdn = host === "@" ? `${domain}.` : `${host}.${domain}.`;
  // Relative host label, empty at the apex — for panels (e.g. Cosmotown) whose
  // Host field is left blank for the root domain rather than written as "@".
  ctx.subhost = host === "@" ? "" : host;
  // SRV panels (e.g. GoDaddy) that split the "_service._protocol" label into
  // separate Service/Protocol fields, leaving Name as whatever remains ("@" at
  // the apex, which is where all our SRV records live). Only meaningful for SRV.
  const labels = host.split(".");
  ctx.service = labels[0];
  ctx.protocol = labels[1] ?? "";
  ctx.srvhost = labels.slice(2).join(".") || "@";
  // Like srvhost but blank (not "@") at the apex — for Hover's SRV form, whose
  // optional Subdomain field is left empty for the root domain.
  ctx.srvsubhost = labels.slice(2).join(".");
  // Service/protocol WITHOUT the leading underscore — for Plesk-based panels
  // (METANET), whose Service-Name/Protokoll fields are documented as taking the
  // bare name ("Beispiel: SIP (ohne Unterstrich)"): "imaps"/"tcp", not "_imaps"/"_tcp".
  ctx.bareservice = ctx.service.replace(/^_+/, "");
  ctx.bareprotocol = ctx.protocol.replace(/^_+/, "");
  return ctx;
}

function interpolate(template, ctx) {
  return template.replace(TOKEN, (_, k) => String(ctx[k]));
}

function valueOf(ctx, cfg, key) {
  return interpolate(cfg.value_templates[ctx.type][key], ctx);
}

// [priority, "port target"] from an SRV record string: the number the relational
// check compares, and the identity of the service endpoint. null unless the string is
// four space-separated fields with a numeric priority, so a malformed record can never
// match. "[0-9]" rather than "\d" to stay identical to the Python twin, whose "\d"
// would also match non-ASCII digits.
function srvParts(record) {
  const parts = record.trim().split(/\s+/);
  if (parts.length !== 4 || !/^[0-9]+$/.test(parts[0])) return null;
  return [Number(parts[0]), `${parts[2]} ${parts[3]}`];
}

// Status of `expected` against every answer at its name: "ok", "missing", or (SRV
// only) "conflict".
//
// mode "exact" (MX/CNAME) requires a whole-record equality so a target with extra
// labels appended (e.g. a missing trailing dot turning "mail.thundermail.com" into
// "mail.thundermail.com.example.com") fails; mode "contains" (TXT) keeps the substring
// test the prefix fragments (MTA-STS/TLSRPT/DMARC) rely on.
//
// mode "srv_lowest_priority" (SRV) is the relational rule from
// thunderbird-accounts#1163: port and target must match exactly, the weight is not
// compared (it only splits load between competing targets at the same priority, and we
// publish a single target — plus Plesk/METANET offers only a fixed dropdown of
// weights), and the priority is judged against the other answers instead of against
// our published number: our target must carry a strictly LOWER priority number than
// any other target at that name. So a working setup at priority 10 passes, while our
// record tied with or out-ranked by someone else's is a "conflict" — it is published
// but may not win. Unparseable answers are ignored for that comparison (they can't be
// ranked), but never match. Case-insensitive; kept in sync with the CLI.
function checkAnswers(expected, answers, mode) {
  const exp = expected.toLowerCase();
  if (mode === "exact") {
    return answers.some((a) => a.toLowerCase() === exp) ? "ok" : "missing";
  }
  if (mode === "srv_lowest_priority") {
    const want = srvParts(exp);
    if (want === null) return "missing";
    const parsed = answers.map((a) => srvParts(a.toLowerCase())).filter((p) => p !== null);
    const ours = parsed.filter(([, key]) => key === want[1]).map(([prio]) => prio);
    if (!ours.length) return "missing";
    const best = Math.min(...ours);
    const outranked = parsed.some(([prio, key]) => key !== want[1] && prio <= best);
    return outranked ? "conflict" : "ok";
  }
  return answers.some((a) => a.toLowerCase().includes(exp)) ? "ok" : "missing";
}

// The FAIL line's explanation: what we wanted, or why what's there conflicts.
// Kept in sync with failure_text() in verify_thundermail_dns.py.
function failureText(mode, status, expected) {
  if (status === "conflict") return CONFLICT;
  return `${VERBS[mode] ?? "expected to contain"}: ${expected}`;
}

function renderFix(cfg, provider, ctx) {
  // Long form: header + labelled fields for a single record.
  const block = cfg.providers[provider][ctx.type];
  const width = Math.max(...block.fields.map(([lbl]) => lbl.length)) + 1;
  const lines = [block.header];
  for (const [lbl, tpl] of block.fields) {
    lines.push(`    ${(lbl + ":").padEnd(width)} ${interpolate(tpl, ctx)}`);
  }
  return lines;
}

// Failing records grouped by type, in record order — the shape both the compact
// on-screen tables and the copied Markdown tables are built from.
function groupByType(ctxs) {
  const groups = new Map();
  for (const ctx of ctxs) {
    if (!groups.has(ctx.type)) groups.set(ctx.type, []);
    groups.get(ctx.type).push(ctx);
  }
  return groups;
}

// Compact form: provider header, then a table with one column per field and one
// row per failing record of the same type. Built from DOM nodes (textContent
// only) so it stays within the CSP — no innerHTML.
function fixTable(cfg, provider, rtype, ctxs) {
  const block = cfg.providers[provider][rtype];
  const wrap = el("div", "fix");
  wrap.appendChild(el("p", "fixhdr", block.header));
  const table = el("table", "fixtable");
  const htr = el("tr");
  for (const [lbl] of block.fields) htr.appendChild(el("th", null, lbl));
  table.appendChild(el("thead", null)).appendChild(htr);
  const tbody = el("tbody");
  for (const ctx of ctxs) {
    const tr = el("tr");
    for (const [lbl, tpl] of block.fields) tr.appendChild(fixCell(lbl, interpolate(tpl, ctx)));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

// What actually belongs in the panel's field. A field template may append an
// inline hint after a run of spaces (namecheap's CNAME `Value` carries
// "(no trailing dot)"), which is guidance for the reader — useful on screen and in
// the CLI, but it must never ride along into the panel on a paste. So: the
// clipboard gets everything up to the first run of two-plus spaces. Every real
// value (SRV "0 0 443 host", SPF, …) is single-spaced, so nothing else is touched.
const copyValue = (s) => s.split(/\s{2,}/)[0];

// One table cell: the value, plus a "⧉" button that copies just that value
// (issue #17). Entering these records is a field-by-field job with the provider's
// panel open in the next tab, which is what the section-level "Copy fix
// instructions" (whole block, as Markdown, for email/issues) doesn't serve.
// A blank value — the apex host on bunny/cosmotown/ovh/porkbun/metanet-plesk —
// says "(leave blank)" so an empty cell reads as deliberate rather than as a bug,
// and gets no button: there is nothing to paste, and offering a copy of "" would
// only ever look like it failed.
function fixCell(label, value) {
  const td = el("td");
  const copy = copyValue(value);
  td.appendChild(el("span", copy ? "cellval" : "cellval blank", copy || "(leave blank)"));
  if (value !== copy) td.appendChild(el("span", "cellhint", value.slice(copy.length).trim()));
  if (copy) {
    td.appendChild(copyButton("⧉", copy,
      { cls: "cell", ok: "✓", fail: "✗", aria: `Copy ${label}: ${copy}` }));
  }
  return td;
}

// --- DNS query (the one genuinely platform-specific piece: DoH here) ----------

async function query(resolver, name, type) {
  const r = RESOLVERS[resolver];
  const resp = await fetch(r.url(name, type), { headers: r.headers });
  if (!resp.ok) throw new Error(`DoH HTTP ${resp.status}`);
  const data = await resp.json();
  const answers = data.Answer || [];
  return answers
    .filter((a) => a.type === TYPE_NUM[type])
    .map((a) => a.data.replace(/^"+|"+$/g, "").replace(/\.$/, ""));
}

// --- UI -----------------------------------------------------------------------

const $ = (id) => document.getElementById(id);
let CFG = null;

async function loadConfig() {
  const resp = await fetch("records.json");
  CFG = await resp.json();
  const sel = $("provider");
  for (const name of Object.keys(CFG.providers).sort()) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    sel.appendChild(opt);
  }
}

// --- bookmarkable URL state --------------------------------------------------
// Form state lives in the query string so a link can be bookmarked/shared and
// re-run. Values are only ever assigned to input.value / select.value (never
// innerHTML) and untrusted params are validated against known option sets before
// use, so this adds no XSS surface and needs no CSP/connect-src change.

function applyStateFromUrl() {
  const params = new URLSearchParams(location.search);
  const domain = params.get("domain");
  if (domain) $("domain").value = domain.trim().replace(/\.$/, "");
  const provider = params.get("provider");
  if (provider !== null && (provider === "" || provider in CFG.providers)) {
    $("provider").value = provider;
  }
  const resolver = params.get("resolver");
  if (resolver && resolver in RESOLVERS) $("resolver").value = resolver;
  const fixformat = params.get("fixformat");
  if (fixformat === "table" || fixformat === "long") $("fixformat").value = fixformat;
  // A shared/bookmarked link that names a domain runs immediately.
  if ($("domain").value) $("form").requestSubmit();
}

function stateParams() {
  const params = new URLSearchParams();
  const domain = $("domain").value.trim().replace(/\.$/, "");
  if (domain) params.set("domain", domain);
  if ($("provider").value) params.set("provider", $("provider").value);
  // Omit the defaults (cloudflare / table) to keep shared URLs tidy.
  if ($("resolver").value && $("resolver").value !== "cloudflare")
    params.set("resolver", $("resolver").value);
  if ($("fixformat").value && $("fixformat").value !== "table")
    params.set("fixformat", $("fixformat").value);
  return params;
}

function updateUrl() {
  const qs = stateParams().toString();
  history.replaceState(null, "", qs ? `${location.pathname}?${qs}` : location.pathname);
}

// Absolute form of the same bookmarkable link, for pasting into an email or a
// GitHub issue so the recipient can re-run the very same check.
function shareUrl() {
  const qs = stateParams().toString();
  return new URL(qs ? `?${qs}` : ".", location.href).href;
}

// --- paste-ready copy (web-only) ----------------------------------------------
// Results and fix instructions get pasted into support email and GitHub issues,
// so each section offers a button that puts a Markdown version on the clipboard
// (Markdown keeps the tables legible on GitHub and still reads fine as plain
// text in mail). The text is built from the check's own data, never scraped out
// of the DOM, and nothing here needs a CSP change: no inline script, no
// innerHTML. The CLI has neither a clipboard nor a URL, so — like the
// bookmarkable-URL feature — this is deliberately not mirrored in Python.

// DNS answers are attacker-influenced and end up in someone's terminal or
// editor after a paste, so strip control bytes (the web twin of the CLI's
// sanitize()) and keep the same length cap as the on-screen values.
const clean = (s) => cap(String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, "\uFFFD"));

// A cell can't contain a raw "|" (it would split the Markdown table) or a line
// break — which is flattened to a space before clean() gets to it, so a wrapped
// value stays readable instead of turning into a replacement char. Blank cells
// are spelled out, since an empty one in an email reads as an omission rather
// than as "leave this field empty".
const mdCell = (s) =>
  clean(String(s).replace(/\s*[\r\n]+\s*/g, " ")).replace(/\|/g, "\\|") || "(leave blank)";
const mdRow = (cells) => `| ${cells.join(" | ")} |`;

// Provider blocks we haven't confirmed end-to-end open with an internal caveat
// sentence ("UNVERIFIED — confirm the field labels against your panel."). That's
// a note to us, not to the domain owner we're sending instructions to, so the
// copied text drops that first sentence and keeps the panel navigation after it.
function publicHeader(header) {
  if (!header.startsWith("UNVERIFIED")) return header;
  const cut = header.indexOf(". ");
  return cut === -1 ? header.replace(/^UNVERIFIED\s*—\s*/, "") : header.slice(cut + 2);
}

function resultsMarkdown(domain, resolver, passed, rows, url) {
  const out = [
    `**Thundermail DNS check — ${domain}**`,
    "",
    `${passed} passed, ${rows.length - passed} failed · resolver: ${RESOLVERS[resolver].label}`,
    "",
    mdRow(["Status", "Record", "Expected", "Found"]),
    mdRow(["---", "---", "---", "---"]),
  ];
  for (const r of rows) {
    // A published-but-out-ranked SRV gets its own status word: "FAIL" would send the
    // reader looking for a missing record instead of a competing one.
    const status = r.ok ? "OK" : r.status === "conflict" ? "**CONFLICT**" : "**FAIL**";
    out.push(mdRow([status, r.record, mdCell(r.expected), mdCell(r.found)]));
  }
  out.push("", `Re-check: ${url}`);
  return out.join("\n");
}

function fixesMarkdown(cfg, provider, domain, failures, format, url) {
  const out = [`**How to fix ${failures.length} record(s) in ${provider} — ${domain}**`, ""];
  if (format === "long") {
    for (const ctx of failures) {
      const block = cfg.providers[provider][ctx.type];
      out.push(`### ${ctx.type} ${ctx.label ?? ctx.host}`, "", publicHeader(block.header), "", "```");
      const width = Math.max(...block.fields.map(([lbl]) => lbl.length)) + 1;
      for (const [lbl, tpl] of block.fields) {
        const v = clean(interpolate(tpl, ctx)) || "(leave blank)";
        out.push(`${(lbl + ":").padEnd(width)} ${v}`);
      }
      out.push("```", "");
    }
  } else {
    for (const [rtype, ctxs] of groupByType(failures)) {
      const block = cfg.providers[provider][rtype];
      out.push(publicHeader(block.header), "");
      out.push(mdRow(block.fields.map(([lbl]) => lbl)));
      out.push(mdRow(block.fields.map(() => "---")));
      for (const ctx of ctxs) {
        out.push(mdRow(block.fields.map(([, tpl]) => mdCell(interpolate(tpl, ctx)))));
      }
      out.push("");
    }
  }
  out.push(`Re-check: ${url}`);
  return out.join("\n");
}

async function writeClipboard(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through: the async Clipboard API also rejects when the document
      // isn't focused, and it doesn't exist at all outside a secure context.
    }
  }
  const ta = el("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  ta.remove();
  return ok;
}

// `label` is the resting text; a click swaps in the feedback wording for 2s. The
// section buttons use the default "Copied ✓"/"Copy failed"; per-cell buttons pass
// the compact glyph pair (opts.ok/opts.fail) since that text doesn't fit in a
// table column, plus an extra class for styling and an aria-label — "⧉" on its own
// is not a label.
function copyButton(label, text, opts = {}) {
  const btn = el("button", opts.cls ? `copy ${opts.cls}` : "copy", label);
  btn.type = "button";
  if (opts.aria) {
    btn.setAttribute("aria-label", opts.aria);
    btn.title = opts.aria;
  }
  btn.addEventListener("click", async () => {
    const ok = await writeClipboard(text);
    btn.textContent = ok ? (opts.ok ?? "Copied ✓") : (opts.fail ?? "Copy failed");
    btn.classList.toggle("done", ok);
    setTimeout(() => {
      btn.textContent = label;
      btn.classList.remove("done");
    }, 2000);
  });
  return btn;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

async function runCheck(evt) {
  evt.preventDefault();
  const domain = $("domain").value.trim().replace(/\.$/, "");
  if (!domain) return;
  const provider = $("provider").value;
  const resolver = $("resolver").value;

  updateUrl(); // reflect current form state into the (bookmarkable) URL

  if (!HOSTNAME.test(domain)) {
    $("results").replaceChildren();
    $("resultsactions").replaceChildren();
    $("fixes").replaceChildren();
    $("summary").textContent = `“${domain}” is not a valid domain name.`;
    return;
  }

  $("check").disabled = true;
  $("summary").textContent = `Checking ${domain}…`;
  $("results").replaceChildren();
  $("resultsactions").replaceChildren();
  $("fixes").replaceChildren();

  const url = shareUrl(); // captured now, so a later form edit can't skew the copy
  let passed = 0;
  const failures = [];
  const rows = []; // one entry per record, for the copyable results table
  let currentGroup = null;
  let groupEl = null;

  try {
    for (const rec of CFG.records) {
      if (rec.type !== currentGroup) {
        currentGroup = rec.type;
        groupEl = el("div", "group");
        groupEl.appendChild(el("h2", null, CFG.group_headers[currentGroup]));
        $("results").appendChild(groupEl);
      }

      const ctx = resolveRecord(rec, domain);
      ctx.match = valueOf(ctx, CFG, "match");
      ctx.value = valueOf(ctx, CFG, "value");
      const expected = ctx.match;

      let answers = [];
      let actual = "";
      try {
        answers = await query(resolver, ctx.qname, rec.type);
        actual = answers.join(" / ");
      } catch (e) {
        actual = `(lookup error: ${e.message})`;
      }

      const mode = CFG.value_templates[rec.type].match_mode ?? "contains";
      const status = checkAnswers(expected, answers, mode);
      const ok = status === "ok";
      const row = el("div", "row");
      row.appendChild(el("span", `badge ${ok ? "ok" : "fail"}`, ok ? "OK" : "FAIL"));
      row.appendChild(el("span", "rlabel", labelOf(rec)));
      if (ok) {
        row.appendChild(el("span", "rval", cap(actual)));
        passed++;
      } else {
        row.appendChild(el("span", "rval miss",
          `${failureText(mode, status, expected)}  —  got: ${cap(actual) || "(nothing)"}`));
        failures.push(ctx);
      }
      groupEl.appendChild(row);
      rows.push({
        ok,
        status,
        record: `${rec.type} ${labelOf(rec)}`,
        expected: `${expected}${MATCH_NOTES[mode] ?? " (must contain)"}`,
        found: cap(actual) || "(nothing)",
      });
    }

    $("summary").textContent =
      `Result: ${passed} passed, ${failures.length} failed.`;
    $("resultsactions").appendChild(copyButton(
      "Copy results", resultsMarkdown(domain, resolver, passed, rows, url)));

    if (failures.length && provider) {
      const format = $("fixformat").value;
      $("fixes").appendChild(
        el("h2", null, `How to fix ${failures.length} record(s) in ${provider}:`));
      $("fixes").appendChild(el("div", "actions")).appendChild(copyButton(
        "Copy fix instructions",
        fixesMarkdown(CFG, provider, domain, failures, format, url)));
      if (format === "long") {
        for (const ctx of failures) {
          const card = el("div", "fix");
          card.appendChild(el("h3", null, `${ctx.type} ${ctx.label ?? ctx.host}`));
          card.appendChild(el("pre", null, renderFix(CFG, provider, ctx).join("\n")));
          $("fixes").appendChild(card);
        }
      } else {
        for (const [rtype, ctxs] of groupByType(failures)) {
          $("fixes").appendChild(fixTable(CFG, provider, rtype, ctxs));
        }
      }
    } else if (failures.length) {
      $("fixes").appendChild(el("p", "note",
        'Pick a provider in "Show fixes for" and re-check to see exactly what to enter.'));
    }
  } finally {
    $("check").disabled = false;
  }
}

loadConfig().then(() => {
  $("form").addEventListener("submit", runCheck);
  applyStateFromUrl();
});
