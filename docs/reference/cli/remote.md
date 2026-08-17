---
description: How saw resolves GitHub targets under --remote, --user and --org, and the order in which selectors win.
---

# Remote targeting

`--remote` switches [`scan`](scan.md), [`fix`](fix.md), [`discard`](discard.md) and
[`guard`](guard.md) from local disk to GitHub repositories.
**Scope is local by default and one scope per run** — you always opt in. `--user`/`--org` imply
`--remote`, and under `--remote` a positional must be an `owner/repo` slug; anything else is a hard
error rather than a silently-treated path.

Targets resolve by this ladder, first match wins:

1. **ad-hoc selectors** — `--user` / `--org` and `owner/repo` positionals (these override config);
2. **configured** `targets.github.users` / `orgs`;
3. **your own repositories** — the authenticated user's owned repositories (private included), or a
   GitHub App installation's repositories.
