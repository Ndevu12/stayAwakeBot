---
name: scanner-performance
description: How the stayawake scanner is made fast without changing detection — the utils.parallel concurrency seam, across-repo (#1205) and within-target file-chunk (#1325) parallelism, the concurrency-aware progress board, and the measure-first optimization method (profile → the hotspot is obfuscation, not I/O → prefilter-gate with model-derived necessary anchors). Apply when parallelizing, speeding up a scan, or reviewing perf work.
---

# Scanner performance

Every speedup here is **byte-identical in detection** — prove it (see `security-change-discipline`).

## The concurrency seam — `utils.parallel`

One ordered, error-isolated primitive maps a **pure, picklable** function over a work-list:
`run_ordered(fn, items, *, jobs, backend, on_start, on_done) -> [Outcome]`.

- **Backends by workload:** `PROCESS` for CPU-bound work (local scanning is regex + pure-Python char
  loops that HOLD the GIL, so threads don't help — measured); `THREAD` for I/O-bound (git/API).
- **`jobs <= 1` runs inline** (no pool): zero overhead, the single-item fast path, identical semantics.
- **Order preserved** (results by submission index) → a persisted report is byte-identical at any
  worker count. **Fail-closed:** a worker exception or process death (`BrokenProcessPool`) becomes an
  `Outcome.error`, never a silent drop. **`on_start`/`on_done` fire on the calling thread only**
  (single-writer progress). **Ctrl-C** terminates in-flight workers immediately, no freeze, no orphans
  (terminate the pool's workers BEFORE `shutdown` — `shutdown()` nils `_processes`).
- **Spawn constraint:** worker fns must be module-level and args picklable; the entry module must be
  import-safe (real CLI / `python -m`, not an unguarded heredoc — that error is a harness artifact).

## Two parallelism grains (mutually exclusive → no nested pools)

- **Across-repo (#1205):** a multi-repo sweep scans up to N repos at once via the process pool.
- **Within-target (#1325):** ONE big repo splits its files into **size-balanced chunks** (LPT with a
  file-count tiebreaker so 0-byte/uniform files still spread). The **partitionable** file-based
  matchers run over chunks (`Target.include_only` restricts `iter_files` to the chunk, no re-walk);
  the whole-target matchers run once each; raw findings **merge through the ONE shared
  `scanner.finalize`** (matcher-order → `(-severity, path)` sort) so `-jN` == `-j1` byte-identical.
- A single target uses file-parallelism; a multi-repo sweep stays across-repo. Default `-j` is AUTO
  (small → sequential; big → one worker per core, `settings.parallel_min_files` floor). Speedup scales
  with **PHYSICAL** cores (`os.cpu_count()` counts hyperthreads; CPU-bound work won't exceed physical).

## Progress: concurrency-aware (`utils.progress`)

A multi-line live board with a SINGLE dedicated render thread (no interleaving); degrades to one plain
line per repo when piped / CI / `--no-stream`. Show DONE and RUNNING distinctly (a bare `0/38` reads
as stuck). Worker stdout/stderr is captured and replayed after the board closes (a pool worker can
never corrupt it, nothing is lost). Guarantee `on_start(i)` fires exactly once and BEFORE `on_done(i)`
(a fast item can complete before its start-signal drains — else it lingers as "in progress").

## The optimization METHOD (measure first; the hotspot is CPU, not I/O)

Profiled truth (#1326): **obfuscation is ~85% of scan time** — CPU inside `analyze_file`; the tree
walk and reads are only ~3.5–11s and **decode is ~0**. So do NOT chase reads/walks or a
read-once/file-major rearchitecture as the primary win — that targets the wrong bottleneck (and a
naive read-once cache measured ~1× because matchers read disjoint subsets). Profile before you refactor.

The high-value, byte-identical lever (shipped in #1326) is a **necessary-condition prefilter** on the
expensive analysis (the pattern `content.py` uses, ~9×): `detect_dropper` provably requires a decode
anchor (`atob`/`Buffer.from`) in **every** arm (nested, variable, shell `sh -c`), so it early-returns
when none is present — ~0% of clean files pay the cost. ~1.9× faster, detection byte-identical.

## PREFILTER SAFETY CONTRACT (a detector optimization is a DETECTION change)

Gating/short-circuiting a detector can silently downgrade it later even when it's byte-identical today.
A skip-gate is safe ONLY with ALL of:
1. **Proven-necessary condition** — the skip fires only when NO detection arm could match. Prove it per
   arm (trace every arm), not by spot tests.
2. **Derived from the taxonomy** — anchors come from the model (`taint.model.DECODE_CALLS`), like the
   detection regexes, so they can't drift; a derivation test pins it.
3. **Same matching engine as the detection** — match with the detector's own `re.IGNORECASE`, NOT
   `str.lower()`: they fold some Unicode differently (`ſ→s`, `İ→i`), which makes a `.lower()` gate
   diverge. Using the same engine removes the case-fold asymmetry class by construction. (See
   `security-hardening-patterns`.)
4. **A PERMANENT differential/fuzz guard** — split the un-gated pipeline out (e.g. `_run_dropper_arms`)
   and assert `gated == un-gated` over a fuzzer seeded from EVERY model taxonomy (incl. the non-anchor
   classes like `CHARCODE_DECODES`) + the fixture corpus, so a future arm keyed off a non-anchored
   decode fails CI. A comment alone is not enough.
Then: byte-identical proof (clean + planted corpora) + adversarial FN-hunt gating the push;
`pin-bump-deferred` (detection unchanged). Cheap I/O wins (memoize the walk) are worth their small
share; a body-vs-flat de-dup is NOT provably byte-identical — leave it.

Related: `security-change-discipline` (byte-identical proof + adversarial gate), `engineering-standard`
(measure-first), `security-hardening-patterns` (fold asymmetry), `saw-architecture`.
