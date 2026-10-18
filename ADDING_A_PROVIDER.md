# How to add a DNS provider

This page is for staff who want the DNS checker to show fix steps for a new DNS
provider. You collect the facts, Claude writes the change, and you check it.
For the full rules, read [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 1. Collect the facts

You need:

- The provider name and its DNS help pages.
- A screenshot of the add-record form for each type: MX, SRV, TXT and CNAME.
  Expand the record-type dropdown in one screenshot, so that we can see which
  types the panel supports.
- If you can get it, a screenshot of the record list with some records in it.
- The provider's nameservers. Run `dig NS <domain>` on a domain at that provider.
- A domain at that provider to test with, for example from the support ticket.

If you only have the help pages, Claude can still add the provider. The fix
steps then start with `UNVERIFIED —` until someone compares them with the panel.

## 2. Open a GitHub issue

Issues are public. Before you add a screenshot, hide the customer's domain and
any account, billing or personal details. If you cannot do that, keep the
screenshots in the TBPRO ticket and write only the ticket number in the issue.

Never write the customer's domain in the issue. Write a placeholder, for
example `porkbun.example.com`.

Put in the issue: the provider name, the help links, the screenshots (or the
ticket number) and the nameservers.

## 3. Ask Claude to implement it

In this repository, ask Claude Code: "Please implement issue #NN". Give it the
test domain in the chat, not in the issue.

## 4. Check the result

1. Check out Claude's branch and run `python3 -m http.server 8000`. Open
   http://localhost:8000/, check the test domain and pick the new provider in
   "Show fixes for".
2. Compare each field name and value in the fix steps with the panel.
3. If you can, add a missing record with the fix steps and check the domain again.
4. If everything matches, ask Claude to merge the branch and close the issue.

If the panel changes later, open a new issue with new screenshots.
