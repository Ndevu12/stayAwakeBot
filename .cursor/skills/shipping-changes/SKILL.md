---
name: shipping-changes
description: The contribution workflow — feature-branch PRs (never push main), rebase on origin/main, bare "Closes #NNNN", CHANGELOG in the same PR, signed commits, the shape of a release PR, and gh-CLI style. Apply whenever committing or opening a PR.
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

## What a pull request body says

**Short, and about what was done — never how.** A reviewer needs the defect, the change, and what
proves it. They do not need the approach, the algorithm, the thresholds, the corpus, or a narrative
of the rounds it took. That belongs in the private tracker, where reasoning about how a check decides
is allowed to live.

The same holds for the commit message and the issue title. A public body that explains the method is
both longer than anyone reads and a disclosure — it hands someone tuning against the tool the part
they cannot get by running it.

A body that is three short paragraphs is usually right. If it needs headings for the method, the
method is in the wrong repository.

## Every user-facing change

- **Update `CHANGELOG.md` `[Unreleased]` in the SAME PR** — don't let it drift.
- Update the relevant `docs/` (reference/cli/index.md / how-to/ / etc.).

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

The version exists **only as the git tag** — never add one to the source tree. Preparing the release
PR is the whole of a contributor's part in it, and it carries exactly three things:

1. Both scanner pins moved to the **same** reviewed SHA — never the commit being released.
2. `[Unreleased]` cut into `## [X.Y.Z] - <date>`, compare links repointed. A tag whose section was
   never cut is refused at release time.
3. The container base digest refreshed, and **the vulnerability gate re-run against the rebuilt
   image before anything is tagged** — the pin is fixed, the advisory feed is not, so an image that
   passed last month can block the publish today.

**A published release is immutable.** A step that fails after the tag exists cannot be repaired by
re-running it, and the version number is spent. Anything checkable before the tag must be checked
before the tag.

## Traps that fail a build after the review looks fine

- **The pins are the releaser's to move, not yours.** A change to the detection engine trips the
  freshness gate; the answer is the **deferral label**, not a bump. Bumping them in an ordinary PR
  moves a consumer-facing pin outside the release meant to own it, and two PRs doing it conflict on
  the same line. They move once, in the release PR — already written under *Releases* below.
- **Renaming a documentation heading breaks every link to it**, and the docs build is strict — a
  dangling anchor fails it. Re-sweep for the old anchor across docs, source and tests *after* the
  rename, not before.
- **A test that fakes the running platform for a whole command run** reaches libraries that key
  their own behaviour off it, and then fails for a reason of its own making. Assert the rule, not
  the platform.
- **A pull request is tested merged with `main`.** A registry that is complete on your branch can be
  incomplete against a probe someone else added while you worked. Rebase before assuming a failure
  is spurious.

## gh-CLI & flags

Descriptive kebab long names + single-letter shorts; drop a word that collides with a command
(`--audit-external` → `--external`). Use `gh` for all GitHub operations. Use judgment + memory; don't
ask questions you can settle from the repo.

Related: `working-with-this-codebase`, `engineering-standard`.
