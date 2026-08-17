---
name: shipping-changes
description: The contribution workflow — feature-branch PRs (never push main), rebase on origin/main, bare "Closes #NNNN", CHANGELOG in the same PR, signed commits, and gh-CLI style. Apply whenever committing or opening a PR.
---

# Shipping changes (contribution workflow)

## Branch & PR

- **Never push to `main`.** Every change goes through a feature-branch PR. **Verify the branch before
  every commit.** Branch off **fresh `origin/main`** (`git pull --ff-only` first); **rebase** feature
  branches on `origin/main`, don't merge stale.
- **Link issues with a BARE `Closes #NNNN`** on its own line in the PR/commit body (not prose) so
  GitHub auto-closes. No AI-assistant footer or co-author trailer.
- **Merge PRs one at a time, oldest-first, and WAIT for the maintainer's GitHub review-approval.**
  Never `--admin`-merge past the CODEOWNERS gate. Merging is the maintainer's call, not yours.
- **Signed commits are required** (repo-local SSH signing). A local `%G?` may show `N` — fine.
- Don't over-produce PRs ("deafening"): align on the reasoning first, then ship focused PRs.

## Every user-facing change

- **Update `CHANGELOG.md` `[Unreleased]` in the SAME PR** — don't let it drift.
- Update the relevant `docs/` (reference/cli.md / how-to/ / etc.).

**What an entry may say.** An entry describes what someone *using* the release observes: new or
changed behaviour, flags, compatibility, and fixes they would notice. It does **not** describe
internal implementation — module layout, refactors, detector or rule internals, thresholds, the
inputs an analysis keys on, coverage gaps, or release-pipeline mechanics. **A change with no
user-visible effect gets no entry at all**, which is the common case for a refactor or a pin bump.

For a **security** entry, state that the fix shipped and what it means for the reader — never the
mechanism, and never the weakness it closed. A changelog is read by everyone, including someone
looking for a way past the scanner, and it is permanent and shipped inside the sdist.

This is the same obligations-not-mechanisms rule the skills follow (see
`.claude/skills/README.md`). The changelog is the highest-volume public surface in the repo — it
grows with every PR — so it is where the rule matters most and slips most easily.

## Changes under the security subtree

Changes beneath the security bot carry **additional required checks and review obligations** beyond
the ordinary PR flow, and the maintainer owns them. Raise the change and agree the approach **before**
opening the PR rather than discovering the requirements from a red check.

## Releases

**Releases are the maintainer's, not yours.** Don't cut, tag, or publish one; don't add automation
that force-pushes consumer-pinned refs or bumps versions without review. Prefer SHA-pinning.

## gh-CLI & flags

Descriptive kebab long names + single-letter shorts; drop a word that collides with a command
(`--audit-external` → `--external`). Use `gh` for all GitHub operations. Use judgment + memory; don't
ask questions you can settle from the repo.

Related: `working-with-this-codebase`, `engineering-standard`.
