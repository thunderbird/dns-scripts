// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// provider.html (issue #32): find the DNS provider of a domain without the
// Thundermail record check. Loaded after app.js, whose top-level declarations
// (detect, fixesFor, wantsIssue, issueText, providerSummary, nameserverRows,
// providerMarkdown, copyButton, el, $, HOSTNAME, RESOLVERS, NS_TABLE, …) it
// reuses, so the matching is the same code that the parity tests cover. Like
// app.js it renders with textContent only, so the CSP needs no change.

// The bookmarkable link to this lookup: domain, plus resolver if not the default.
function lookupParams() {
  const params = new URLSearchParams();
  const domain = $("domain").value.trim().replace(/\.$/, "");
  if (domain) params.set("domain", domain);
  if ($("resolver").value !== "cloudflare") params.set("resolver", $("resolver").value);
  return params;
}

function lookupUrl() {
  const qs = lookupParams().toString();
  return new URL(qs ? `?${qs}` : location.pathname, location.href).href;
}

// The full check on the main page, with the detected provider's fix steps.
function checkerUrl(domain, provider, resolver) {
  const params = new URLSearchParams({ domain, provider });
  if (resolver !== "cloudflare") params.set("resolver", resolver);
  return new URL(`index.html?${params}`, location.href).href;
}

function link(text, href, external = false) {
  const a = el("a", null, text);
  a.href = href;
  if (external) {
    a.target = "_blank";
    a.rel = "noopener";
  }
  return a;
}

async function runLookup(evt) {
  evt.preventDefault();
  const domain = $("domain").value.trim().replace(/\.$/, "").toLowerCase();
  if (!domain) return;
  const resolver = $("resolver").value;
  const qs = lookupParams().toString();
  history.replaceState(null, "", qs ? `${location.pathname}?${qs}` : location.pathname);

  $("results").replaceChildren();
  $("resultsactions").replaceChildren();
  if (!HOSTNAME.test(domain)) {
    $("summary").textContent = `“${domain}” is not a valid domain name.`;
    return;
  }

  $("check").disabled = true;
  $("summary").textContent = `Looking up ${domain}…`;
  const url = lookupUrl();
  try {
    const [zone, result] = await detect(resolver, domain);
    $("summary").textContent = `DNS provider for ${domain}: ${providerSummary(result)}`;
    if (zone && zone !== domain) $("results").appendChild(el("p", "note", `Zone: ${zone}`));

    const rows = nameserverRows(result);
    if (rows.length) {
      const table = el("table", "nstable");
      const htr = el("tr");
      htr.append(el("th", null, "Nameserver"), el("th", null, "Provider"));
      table.appendChild(el("thead")).appendChild(htr);
      const tbody = el("tbody");
      for (const [host, name] of rows) {
        const tr = el("tr");
        tr.append(el("td", null, clean(host)), el("td", null, name));
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      $("results").appendChild(table);
    }

    const fixes = fixesFor(result);
    const fixUrl = fixes ? checkerUrl(domain, fixes, resolver) : "";
    if (fixUrl) {
      const p = el("p", "nextstep");
      p.append(link("Check the Thundermail records", fixUrl),
        ` with the fix steps for ${fixes}.`);
      $("results").appendChild(p);
    }
    if (wantsIssue(result)) {
      const p = el("p", "nextstep");
      p.append("There are no fix steps for this provider yet. To request them, ",
        link("file a GitHub issue", `${ISSUE_URL}?${new URLSearchParams(issueText(result))}`, true),
        ".");
      $("results").appendChild(p);
    }

    $("resultsactions").appendChild(
      copyButton("Copy result", providerMarkdown(domain, zone, result, fixUrl, url)));
  } catch (e) {
    $("summary").textContent = `Lookup failed: ${e.message}`;
  } finally {
    $("check").disabled = false;
  }
}

async function initProviderPage() {
  try {
    NS_TABLE = (await (await fetch("nameservers.json")).json()).providers;
  } catch {
    $("summary").textContent = "Could not load nameservers.json. Reload the page to try again.";
    return;
  }
  $("form").addEventListener("submit", runLookup);
  // Bookmarkable state. Untrusted values only go into input.value / select.value,
  // and the domain still passes the hostname regex before any lookup.
  const params = new URLSearchParams(location.search);
  const domain = params.get("domain");
  if (domain) $("domain").value = domain.trim().replace(/\.$/, "");
  const resolver = params.get("resolver");
  if (resolver && resolver in RESOLVERS) $("resolver").value = resolver;
  if ($("domain").value) $("form").requestSubmit();
}

initProviderPage();
