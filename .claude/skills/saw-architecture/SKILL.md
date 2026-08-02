---
name: saw-architecture
description: The layered package structure of stayawake (utils→lib→core→bots→cli) and where code belongs. Use when adding a module, deciding a layer, moving code, splitting an over-long file, or wiring a shared seam. Enforced by tests/core/test_layering.py.
---

# saw / stayawake — architecture

`src/stayawake/` is a **strict 5-layer** package; imports may only go to a **strictly lower** layer.
`tests/core/test_layering.py` walks the full AST (lazy imports count) and fails any upward import.

```
utils/  →  lib/  →  core/  →  bots/  →  cli/
```

- **`utils/`** — pure, dependency-free helpers: `render`, `textsafe`, `config`, `env`, `io`,
  `streaming`, `progress`, `parallel`, `terminal`, `pager`, `timeutil`.
- **`lib/`** — external-system adapters: `lib.adapters.{github_api,http_client,slack}`, `lib.git`
  (the git-CLI package), `lib.auth`, `lib.github_app`, `lib.jwtsign`.
- **`core/`** — domain layer: `core.issue_state` (issue-as-state-store), `core.proposal`
  (propose-a-change-as-PR + fork→patch→issue ladder), `core.identity`.
- **`bots/`** — `bots.security` (the worm engine) and `bots.health`.
- **`cli/`** — argparse commands + dispatch.

## Rules that keep it clean

- **When a lower layer needs higher behavior, INJECT a callable** — never import up. (e.g. a
  `lib/git` merge helper takes `content_sig`/`obfuscation_reason` as parameters.)
- **Grep LAZY imports (inside functions) too** before deciding a layer — a lazy `core.X` import makes
  a module `core`, not `lib`.
- **Read env only via `utils.env`** accessors (name constants + `get()`/`github_slug()`/…), never
  scattered `os.environ.get`.
- **All git operations live in ONE `core.git`-style package** split per concern
  (`run`/`auth`/`query`/`merge`/`write`); a flat re-export keeps callers churn-free.
- **Reuse shared seams, don't duplicate:** `core.proposal.submit_change_pr` (the PR ladder),
  `resolution` (target resolution + `cloned_repo`), `utils.textsafe` (injection-safe encoding),
  `utils.parallel` (ordered concurrency) — shared by scan/fix/guard.

## Splitting an over-long module into a package (the byte-identical method)

Split `bots/security/*.py` into per-concern packages **byte-identically**: slice verbatim (or
AST-extract interleaved sections), **prove each section is byte-identical vs HEAD**, keep the suite
green as the ratchet, expose a **clean facade** (`__init__` re-exports the public API only — no private
re-exports, zero unused imports), and repoint mocks/private-access to the submodule. Landmines seen:
submodule↔function name collisions (rename), cross-submodule mock namespaces, and BSD `sed` lacking
`\b`. Do NOT fragment cohesive logic just to hit a line count — honest SRP, not over-splitting.

**Gitignore gotcha:** the stock Python `.gitignore` had an unanchored `lib/` rule that silently
skipped `src/stayawake/lib/` (wheel missing the package → CI-only `ModuleNotFoundError`). When adding
a top-level source package, run `git check-ignore` on its new files.

Canonical docs: `docs/ARCHITECTURE.md`, `docs/SECURITY_ARCHITECTURE.md`, `CONTRIBUTING.md`.
