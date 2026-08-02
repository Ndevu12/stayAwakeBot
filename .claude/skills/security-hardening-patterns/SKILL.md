---
name: security-hardening-patterns
description: Recurring low-level hazards and their fixes in stayawake — ReDoS-safe regexes, GitHub Actions log-injection defanging, injection-safe rendered bodies, GitHub App installation-token preflight, non-regular-file (FIFO) read guards, and commit-signing in worktrees. Apply when writing a regex/matcher, rendering untrusted text, calling the GitHub API, reading arbitrary files, or committing programmatically.
---

# Security-hardening patterns (recurring gotchas)

## ReDoS-safe regexes

- **Bound the QUANTIFIER, not the input.** A length cap on the input creates a code-visible
  detection-evasion boundary (pad past it); a bounded quantifier (`{0,2048}`, or a possessive
  `{0,512}+` when the class excludes the delimiter) is detection-identical and kills the backtrack.
- **Compile regexes at MODULE level** (an inline f-string regex hid a cubic pattern from the guard).
- Prefer a **linear `str.find`** for opener/closer scanning over a quadratic `$`-anchored regex.
- **One shared guard** (`tests/.../test_redos_safety.py`) over every module-level regex, not per-file
  tests. Beware false-green ReDoS fixtures sized just OVER the read cap (never reach the regex).

## GitHub Actions log injection

Untrusted text in a CI surface can inject workflow commands. `::cmd::` is parsed at line-start, but
the **legacy `##[cmd]` form is matched ANYWHERE in a line** (per `actions/runner`) — **defang BOTH**.
In Markdown bodies, wrap attacker-influenced fields in a `` `code` `` span (bare sanitize still leaves
`[]()` active); map bidi/control chars to space; cap lists. Route untrusted fields through
`utils.textsafe`.

## GitHub App / API

- **Installation-token preflight:** the Actions `GITHUB_TOKEN` 403s on `GET /user`
  (`enabledForGitHubApps=false`). Validate via `GET /repos/{slug}` (metadata:read) or `/rate_limit`.
  GitHub 401s a bad token before resource visibility → treat auth failures as fatal (fail closed).
- A per-owner GitHub App installation is per-account; resolve the installation that OWNS each repo.

## Reading arbitrary files

**Guard against non-regular files** (`stat` + `S_ISREG` BEFORE `open`) — a FIFO named `evil.js` hangs a
blocking `open()` forever. Skip non-regular as a BENIGN skip (not a gap). Any code that walks a tree
and opens files itself (e.g. an installed-package audit walking `node_modules`) needs the same guard.
Never claim "clean" over content you did not fully READ (a `--verify` that hit an unreadable/oversized/
non-regular entry reports the gap, CONFIRMED-tier only).

## Case-folding: `str.lower()` ≠ `re.IGNORECASE`

When a fast-path check must agree with a case-insensitive regex — e.g. a prefilter that decides
whether to run a `re.IGNORECASE` detector — **match with the regex engine (`re.IGNORECASE`), not
`str.lower()`.** They fold some Unicode differently: `re.IGNORECASE` folds `ſ`(U+017F)→`s`,
`İ`(U+0130)→`i`, but `'ſ'.lower() == 'ſ'`. A `.lower()` substring gate therefore diverges from the
regex on adversarial homoglyphs. Using a compiled anchor regex with the same flag makes the gate open
exactly when the detector could match — no asymmetry (see the prefilter contract in
`scanner-performance`). `str.casefold()` is closer but still not guaranteed identical to `re`'s folding.

## Committing programmatically

A programmatic commit inherits `commit.gpgsign=true` and **fails in a worktree** — and a
`check=False` subprocess call **swallows** the failure (→ phantom "prepared N", empty branch). Check
the return code, retry with `-c commit.gpgsign=false`, and WARN (the retry does NOT bypass hooks).
Sweep out `check=False` where a silent failure would mislead — fail loud.

Every one of these was found by adversarial verification catching a real bug the green suite missed —
see `security-change-discipline`.
