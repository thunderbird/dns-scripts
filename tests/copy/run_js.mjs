// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copy-button harness: load app.js in a sandbox and run its paste-ready text
// builders (publicHeader / mdCell / resultsMarkdown / fixesMarkdown / shareUrl)
// over a spec fed in on stdin, so tests/test_copy.py can assert on the output.
//
// These functions are web-only — the CLI has neither a clipboard nor a URL — so
// unlike tests/parity/run_js.mjs there is no Python twin to compare against;
// the expectations live in the Python test.
//
// Same load-time contract as the parity harness: app.js is a plain browser
// script whose only top-level side effect is the trailing `loadConfig().then()`,
// neutralised by a `fetch` that never settles. This sandbox additionally needs
// `URL` and a real `location.href` (shareUrl builds an absolute link) and form
// fields with values (stateParams reads them). If app.js gains new load-time
// code touching browser globals, extend these stubs (see CLAUDE.md → Testing).

import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");
const appSrc = fs.readFileSync(path.join(repoRoot, "app.js"), "utf8");

const spec = JSON.parse(fs.readFileSync(0, "utf8"));
const cfg = spec.cfg;

const noop = () => {};
const domNode = { addEventListener: noop, appendChild: noop, replaceChildren: noop };
const sandbox = {
  fetch: () => new Promise(noop),
  document: {
    // The form inputs stateParams() reads; anything else gets an empty value.
    getElementById: (id) => ({ ...domNode, value: spec.form[id] ?? "" }),
    createElement: () => domNode,
  },
  history: { replaceState: noop },
  location: { pathname: new URL(spec.location).pathname, search: "", href: spec.location },
  URLSearchParams,
  URL,
  Promise,
  console,
};
sandbox.window = sandbox;
vm.createContext(sandbox);
// `function` declarations land on the sandbox global, but `const` ones (mdCell
// and friends) only exist in the script's lexical scope — so an epilogue run as
// part of the same script hands them out. Keeps app.js free of test scaffolding.
vm.runInContext(`${appSrc}\nglobalThis.__copy = { mdCell };`, sandbox,
                { filename: "app.js" });

const { resolveRecord, publicHeader, resultsMarkdown, fixesMarkdown, shareUrl } = sandbox;
const { mdCell } = sandbox.__copy;
const valueOf = sandbox.valueOf; // own global prop shadows Object.prototype.valueOf

// A failing record, as runCheck() would have built it before handing it to the
// fix renderers.
function ctxFor(host, type, domain) {
  const rec = cfg.records.find((r) => r.host === host && r.type === type);
  if (!rec) throw new Error(`no ${type} record with host ${host}`);
  const ctx = resolveRecord(rec, domain);
  ctx.match = valueOf(ctx, cfg, "match");
  ctx.value = valueOf(ctx, cfg, "value");
  return ctx;
}

const out = {
  shareUrl: shareUrl(),
  publicHeaders: spec.publicHeaderCases.map(publicHeader),
  providerHeaders: spec.providerHeaderCases.map(([p, t]) => publicHeader(cfg.providers[p][t].header)),
  cells: spec.cellCases.map(mdCell),
  results: resultsMarkdown(
    spec.resultsCase.domain, spec.resultsCase.resolver, spec.resultsCase.passed,
    spec.resultsCase.rows, spec.resultsCase.url),
  fixes: spec.fixCases.map((c) => fixesMarkdown(
    cfg, c.provider, c.domain,
    c.records.map(([host, type]) => ctxFor(host, type, c.domain)),
    c.format, c.url)),
};

process.stdout.write(JSON.stringify(out));
