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

Profiled truth on a real tree: **obfuscation is ~85% of scan time**; the tree walk (`os.walk` × per
matcher) and reads are only ~3.5–11s and **decode is ~0**. So do NOT chase reads/walks or a
read-once/file-major rearchitecture as the primary win — that targets the wrong bottleneck.

The high-value, byte-identical lever is a **necessary-substring prefilter** on the expensive analysis
(the pattern `content.py` already uses, ~9×): the `detect_dropper` flow provably requires a decode
anchor (`atob`/`Buffer.from`) in **every** arm (nested, variable, and shell `sh -c` arms) — gate it on
that anchor and ~0% of clean files pay the cost. **Derive the anchor from the taxonomy**
(`taint.model.DECODE_CALLS`) so it can never drift, and pin it with a derivation test. This is a
detection-path change → verify byte-identical + adversarial FN-hunt (is the anchor truly necessary for
every arm?) before merge; `pin-bump-deferred` (detection unchanged). Cheap I/O wins (string-path
`iter_files` + memoize the walked list) are worth their small share; a body-vs-flat de-dup is NOT
provably byte-identical — leave it.

Related: `security-change-discipline` (byte-identical proof + adversarial gate), `engineering-standard`
(measure-first), `saw-architecture` (`utils.parallel`, matcher layering).
