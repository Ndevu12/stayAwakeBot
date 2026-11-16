---
name: rust-rebuild
description: The rules for rebuilding saw as a Rust program — what the restructuring may and may not change, how the long-lived rebuild branch and its feature branches are cut, how main and the rebuild stay in step, and when the rebuild merges into main. Apply to any work on the rebuild, and to any change on main while the rebuild is open.
---

# The Rust rebuild

`saw` is being rebuilt as one Rust program on a single engine. The rebuild lives on its own branch
until it replaces `main` whole. These rules hold until that merge.

## Restructuring

- **Work only from the plan.** Every change belongs to one item of one milestone of the rebuild
  epic in the maintainer's tracker. Milestones go in order; a change that belongs to no item is not
  made. One pull request carries one item.
- **Promote what is sound, rebuild the rest.** Signature data, fixtures, command-level tests, docs and
  wording carry over as they are. Code is rebuilt in Rust, not translated line by line.
- **Nothing is left behind.** Every behaviour, command, flag, document and practice `main` has
  carries over. A behaviour is dropped only by a maintainer's decision recorded in the plan.
- **Zero downgrade, proven.** The rebuild's findings, verdicts and removals equal `main`'s on the
  shared corpus, byte for byte, except the changes the plan lists. A difference that is not listed is
  a defect, whichever side looks better.
- **Known bugs are in scope, inside their milestone.** A reported bug enters as a reproduction test
  in the milestone that rebuilds the part it lives in, and that milestone closes with it passing.
  There is no separate bug track, and no drifting into bug work outside the plan.
- **No Python at runtime.** The shipped tool is Rust. Python stays for development tooling only:
  the parity harness, the wording check, the pin tools, the docs build and the test suite.
- **Depend on as little outside code as possible.** Only crates in the dependency record may be
  used. Every accepted crate has a planned way out and a review milestone. The count of crates in
  the shipped tool only goes down; raising it needs the maintainer's approval and a new entry in the
  record first.
- **The layers hold.** Each crate may depend only on the crates the allowed-edges list names for it.
  `unsafe` code lives only in the platform crate.
- **Decided in planning, executed in implementation.** A design or dependency question met during
  implementation goes back to the plan and the maintainer before code is written for it.

## Branching

- **`main` is maintenance only**: security fixes and signature data. Everything else goes to the
  rebuild.
- **`rebuild/one-engine` is the rebuild's integration branch.** Treat it like `main`: never push to
  it directly, never force-push it, never rewrite its history.
- **Feature branches are named `rebuild/<topic>`**, cut from a freshly fetched
  `origin/rebuild/one-engine`, and their pull requests target `rebuild/one-engine`. Rebase a
  feature branch on `origin/rebuild/one-engine` before asking for a merge.
- **A fix on `main` lands on `main` first** and reaches the rebuild through the weekly sync. Where
  the rebuild has already rebuilt that part, the next rebuild pull request for that part carries the
  fix as a reproduction test.
- **Rebuild work never goes to `main` piecemeal.** No cherry-picks, no back-ports of rebuilt parts.

## Merging

- **Weekly sync.** `origin/main` is merged into `rebuild/one-engine` through a pull request from a
  `rebuild/sync-main-<date>` branch, as a merge commit, never a rebase. Conflicts are resolved in
  that pull request and nowhere else; `CHANGELOG.md` keeps both sides.
- **Feature pull requests into the rebuild follow every rule in `shipping-changes`**: signed
  commits, the maintainer's GitHub review approval, merged one at a time and oldest first, no
  `--admin`, a `CHANGELOG.md` `[Unreleased]` entry for a user-visible change, and the wording check.
- **Pre-releases for field testing are the maintainer's**, tagged from `rebuild/one-engine`. Version
  numbers and tags are never proposed by a contributor.
- **The rebuild merges into `main` once, when the merge gate is met:**
  1. every command runs on the new engine;
  2. the corpus is byte-identical with `main` except the listed changes;
  3. every disagreement the plan names between hook, scan, fix and push is gone;
  4. every test passes and every platform builds;
  5. every remaining crate has a written reason.

  That merge is one pull request, and it is the maintainer's call.
