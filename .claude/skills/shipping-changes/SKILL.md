---
name: shipping-changes
description: The contribution workflow for stayawake — feature-branch PRs (never push main), rebase on origin/main, bare "Closes #NNNN", CHANGELOG in the same PR, the pin-bump-deferred label for bots/security/** changes, signed commits, gh-CLI style, and the GitHub publishing environment. Apply whenever committing, opening a PR, or releasing.
---

# Shipping changes (contribution workflow)

## Branch & PR

- **Never push to `main`.** Every change goes through a feature-branch PR. **Verify the branch before
  every commit.** Branch off **fresh `origin/main`** (`git pull --ff-only` first); **rebase** feature
  branches on `origin/main`, don't merge stale.
- **Link issues with a BARE `Closes #NNNN`** on its own line in the PR/commit body (not prose) so
  GitHub auto-closes. No "Claude" footer / co-author trailer.
- **Merge PRs one at a time, oldest-first, and WAIT for the maintainer's GitHub review-approval.**
  Never `--admin`-merge past the CODEOWNERS gate. Merging is the maintainer's call, not yours.
- **Signed commits are required** (repo-local SSH signing). A local `%G?` may show `N` — fine.
- Don't over-produce PRs ("deafening"): align on the reasoning first, then ship focused PRs.

## Every user-facing change

- **Update `CHANGELOG.md` `[Unreleased]` in the SAME PR** — don't let it drift. Match the existing
  keep-a-changelog style (heading then list; the markdown-lint warnings are pre-existing).
- Update the relevant `docs/` (CLI.md / USAGE.md / etc.).

## The scanner pin (CRITICAL — do at PR creation)

For **any PR whose diff touches `src/stayawake/bots/security/**`**, add the **`pin-bump-deferred`**
label **directly in the `gh pr create` command** (unless the PR itself bumps `sentinel-ref`). The
in-band `pin-freshness` REQUIRED check goes RED without it. Also add `security` for a
detection/scanner change. Verify with `gh pr view <n> --json labels`. A perf/refactor/remediation
change under that subtree that detects **byte-identically** still needs the label (defer is correct;
the gate detects identically). Cutting the catch-up pin bump itself is the **maintainer's**
responsibility — offer, don't do it unprompted.

## gh-CLI & flags

Descriptive kebab long names + single-letter shorts; drop a word that collides with a command
(`--audit-external` → `--external`). Use `gh` for all GitHub operations.

## Publishing environment (gotchas)

- gh auth is via keychain. **Push workflow files over SSH** (the token lacks `workflow` scope).
- The `security` ~ALL ruleset can block feature-branch pushes when ON; no force-push to protected refs
  (merge `main` in). CODEOWNERS guards security files.
- **Never stage `.claude/settings.local.json`** (it's gitignored; `settings.json` is shared/committed).
- Releases are **tag-derived** (`hatch-vcs`): cut a release by pushing a **signed tag**, not
  `gh release create` (immutable releases 422 on asset upload). Publish fails closed behind
  build + self-scan; the Docker Trivy gate blocks GHCR on fixable crit/high → bump the SHA-pinned base
  digest (never weaken the gate). See `docs/RELEASING.md`.

## No unreviewed privileged CI automation

Don't add automation that force-pushes consumer-pinned refs or bumps versions without review. Prefer
SHA-pinning. Use judgment + memory; don't ask questions you can settle from the repo.

Related: `working-with-this-codebase`, `security-change-discipline`, `saw-architecture`.
