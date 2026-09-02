# Brief for a parallel agent on `saw` / stayAwakeBot

You are working on the `saw` supply-chain worm scanner alongside another agent. Read this whole
brief before touching anything. It carries what took a long time to learn here; most of it is not
derivable from the code.

---

## 0. Your lane — do not leave it

Another agent is working on the **scan/history axis**. Those files are theirs. **Do not edit:**

```
src/stayawake/bots/security/scanner.py
src/stayawake/bots/security/targets/**
src/stayawake/lib/git/query.py
src/stayawake/cli/commands/scan.py
tests/bots/security/test_history_residue.py
tests/core/test_git_reachable_blobs.py
```

If your work genuinely needs one of them, stop and say so rather than editing.

**Your issues, in this order, one PR each:**

1. **`Ndevu12/saw#232`** — false positive: `obfuscated-source-file` flags Playwright's `page.$eval`.
   Touches `src/stayawake/bots/security/matchers/obfuscation.py`.
2. **`Ndevu12/saw#151`** — an unparseable plist puts its whole body into `shell_lines`.
   Touches the autorun/os-service side of `src/stayawake/bots/security/hygiene/`.
3. **`Ndevu12/saw#208`** — saw's own git template dir is an auto-executing persistence surface.

**Never batch these.** `#232` *narrows* detection and needs its own false-negative hunt; `#151` is a
parsing defect; `#208` touches saw's own surface. Three separate PRs.

---

## 1. Where things live

- **Code** — `Ndevu12/stayAwakeBot` (public). This checkout.
- **Issues, analysis, research** — `Ndevu12/saw` (private), cloned at `~/dev/tools/saw`.
  This split is BY DESIGN. Read issues with `gh issue view N --repo Ndevu12/saw`.
- A bare `Closes #NNNN` in a stayAwakeBot PR resolves against **stayAwakeBot**, so it never closes a
  `saw` issue. Close those by hand after the merge, with a comment recording what shipped, what
  deviated from the issue's ask, and what stays open.

**Rules you must read, in this order:**

| Source | What it holds |
| --- | --- |
| `CLAUDE.md` (repo root) | The always-on summary. Nine rules that cost the most when missed |
| `.claude/skills/saw-overview` | What `saw` is, its verbs, the safety invariants |
| `.claude/skills/engineering-standard` | SRP, naming, **"never document a variable — fix the name"** |
| `.claude/skills/working-with-this-codebase` | Align before consequential work; decide-and-recommend |
| `.claude/skills/shipping-changes` | PR discipline |
| `.cursor/rules/operator-docs-no-exit-codes.mdc` | `alwaysApply` — see §5 |

---

## 2. Running anything — this is the part people get wrong

There is a venv with the project's declared dependencies. **Use it for everything.**

```
VENV=/private/tmp/claude-501/-Users-ndevu-dev-tools-stayAwakeBot/<session>/scratchpad/venv
PYTHONPATH=src "$VENV/bin/python" -m unittest <module>
```

If it is gone, rebuild it — `python3 -m venv`, then `pip install pyyaml aiohttp certifi`. Do **not**
`pip install --user` (PEP 668 refuses it here) and do **not** pass `--break-system-packages`.

**Why this matters more than it looks:** without those dependencies, ~77 test modules fail to
import and `unittest discover` silently skips them — including, reliably, the ones covering whatever
you just changed. A green local run without the venv is not evidence. Two CI failures in one day
came from exactly that.

**Run the repo-wide contract tests every time, not just your module's suite.** They scan every
source file, so any change can break them — one added string literal is enough:

```
tests/core/test_render.py                        # no literal may LEAD a line with a MARKER glyph
tests/core/test_layering.py                      # utils -> lib -> core -> bots -> cli, import down-only
tests/core/test_operator_docs_omit_exit_codes.py
tests/bots/security/test_report_word_budget.py   # 30-word detail / 20-word remediation
tests/test_python_floor.py
```

Re-derive that list with `grep -rln "ast.parse\|rglob\|read_text()" tests/` if it drifts.

---

## 3. Before you implement anything

**Read the issue's comment thread, not its body.** The body records what was believed when it was
filed; the thread records what is true now. A third of the backlog carries corrections, measurements
and reversals in comments with the body left standing.

**Then check the code.** Twice recently an issue turned out to be already satisfied on `main` —
including one the delivery plan called *"the most urgent single item in the record."* Verify before
building; a plan and an issue are both weaker evidence than the repository.

**Measure, do not reason.** If you are about to write "this is rare" or "this is fast", measure it
first. Recent examples where reasoning was wrong and measurement was right: a no-op `chown` returns
success on an immutable directory (so the naive test says the flag permits ownership changes — it
does not); an "opt-in scan takes 17 seconds" figure was produced by code that read nothing.

---

## 4. The engineering bar

- **Never document a variable — fix the name.** A comment above a constant is a name that failed.
  It breaks hardest on lookup tables. If you wrote three lines above a name, move them into the
  function below and see how much survives.
- **Comment density: measure it, do not eyeball it.** Compare
  `(inline-comment lines + docstring lines) / code lines` against the same file on `origin/main`
  before pushing. A docstring that retells a defect belongs in the commit message.
- **Fix, don't file.** A defect found while implementing something belongs in that PR, not in a new
  issue. Filing instead of fixing grows the backlog you were asked to shrink.
- **Tests are the SPEC.** A test failing after your edit means you violated a contract you did not
  read — not that the test needs updating. Read what it protects; if you must change it, keep the
  property it is named for and say in the commit why the expression changed.
- **Reuse before building.** Check whether the answer already exists one module over. It usually
  does, and the existing one usually handles cases yours will not.
- **Right depth, no bandaids.** Fix the class at its boundary, not each symptom.

---

## 5. Publication rules — these are not style

The code repo is **public**. Public PR bodies, commit messages, shipped source, help text and
`docs/` may state that a defect existed and what an operator observes. They may **not** carry:

- thresholds, the inputs a detector keys on, or how it decides;
- coverage gaps, or **a map of where the tool does and does not look** — that tells a reader where
  to hide and tells an operator nothing actionable;
- evasion detail.

Mechanism goes in a `Ndevu12/saw` issue or `analysis/`, which is private.

**Operator docs never mention exit codes.** No `docs/reference/exit-codes.md`, no Exit tables, no
`echo $?` in `docs/`, `README.md`, `SUPPORT.md`, or new `CHANGELOG.md` entries. Operators read the
verdict. CI gating on process status lives in code, tests and skills only.

---

## 6. Detection changes specifically

- **Detectors are tightened, never downgraded.** `#232` narrows one, so it needs its **own** PR and
  its own **false-negative hunt** — an FP-hunt tells you a signal is noisy; it never tells you
  whether removing it opens a hole.
- **A verdict that fires on an ordinary host is a defect.** Before gating anything on a new signal,
  measure its base rate on a real machine. Measure the thing you are actually shipping: a rule about
  directories is not validated by a measurement of files.
- **Widening and narrowing must not share a PR** — together they make FP/FN movement unreadable.
- **Never batch:** a change to a type every check returns; anything that narrows detection; anything
  destructive or that writes to the host.

---

## 7. Proving a change works

**A passing suite is not evidence.** Mutate the source — break the thing your test claims to pin —
and confirm the test fails. Every new guard gets one.

**Check the harness before believing a result.** Mutation harnesses have produced false PASSes here
by: an anchor that no longer matched (silent skip); an anchor that matched a *different* site with
identical text; a test that planted its input where the run exits at an earlier branch, so it never
reached the code it was named for; `mock.Mock(markers=[])`, which answers the one attribute you name
and stubs away the fields carrying the thing under test. Also: `sed -i '' 's/\bNAME\b/…/'` does
**nothing** on macOS — BSD sed has no `\b` — and it reports success. Use Python and assert the edit
landed.

**If a mutation survives, say so.** Do not invent a test that cannot fail to make the table look
clean. Either the guard is unnecessary (delete it) or the case is unreachable today (state it as an
accepted residual).

**Security-critical changes get an adversarial round before the PR leaves draft.** Spawn parallel
verifiers, each told to REFUTE one property, **two items maximum each**, with the lens matched to
the risk: trust/defaults → hunt the silent fail-open; a widened detector → hunt false positives on
realistic code; a **removed** signal → hunt false negatives; a severity change → hunt under-alarm.
Give them the accepted residuals so they do not re-report them. Re-verify on the amended diff —
every round in recent memory found the previous fix's own shadow.

---

## 8. Shipping

```
git fetch -q origin main && git checkout -b <name> origin/main
```

One command. The maintainer merges within minutes, and branching from a stale base has already cost
a rebase and, once, a branch cut from another feature branch.

- **Feature-branch PRs only. Never push `main`.** Commits in stayAwakeBot are **signed**
  (`-c gpg.format=ssh`, key configured); commits in `Ndevu12/saw` are **unsigned** — match the repo.
- Open the PR as **draft** for anything under `bots/security/**`; it leaves draft when an
  adversarial round comes back clean.
- Label `pin-bump-deferred` **in the create command** (a later add loses a race with `pin-freshness`,
  which reads the frozen event payload and can never be fixed by re-running).
- A user-facing change gets a `CHANGELOG.md` `[Unreleased]` bullet **in the same PR**.
- No AI-attribution footer in PR bodies or commit messages.
- **After every push, run `gh pr checks <n>` and read it** before you say anything about the state of
  the work. "The suite passed locally" is a different claim, and a weaker one — CI runs a matrix, and
  a CI runner has no applications installed and no real user home, so it cannot see a whole class of
  defect that a local run can.
- Merging and releasing are the maintainer's. Never `--admin` past a check.

---

## 9. How to work with the maintainer

- **Decide and recommend — never present an option menu.** Lay out context, problem, trade-offs,
  then your recommendation as a decision you are making. If they challenge it, justify or retract
  plainly; do not just fold.
- **Ask before decisive or outward actions** — choosing between real alternatives, removing
  functionality, anything destructive, anything touching a host, a remote, or the tracker. Read-only
  investigation and running tests need no permission.
- **Warn loudly, never fail silently.** An unchecked error or a silent degradation is a defect. When
  asked "is this genuine or just making it work?", name the real caveats — code you could not run,
  tests you wrote yourself, platforms you could not test.
- Answer exactly what was asked. When redirected, drop the previous thread.
- Report faithfully: if tests failed, say so with the output; if you skipped something, say that.

---

## 10. Start here

1. Read `CLAUDE.md` and the four skills.
2. `gh issue view 232 --repo Ndevu12/saw` — **and its comments**.
3. Reproduce the false positive against `main` before changing anything. If it does not reproduce,
   say so and stop; that has happened before.
4. Design, then state your approach and recommendation before writing the fix — `#232` narrows a
   detector, which the maintainer wants agreed first.
