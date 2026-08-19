#!/usr/bin/env python3
"""One sweep runner: map a per-item unit of work over a work-list behind a concurrency-aware
live progress board, returning results in SUBMISSION order.

Every repo-sweeping command (`saw scan` / `fix` / `guard`) needs the SAME orchestration around
`utils.parallel.run_ordered`: open a progress board, fire per-item start/done events at it, run
the items with a bounded worker pool, and hand back ordered `Outcome`s so the caller can fail
closed and render deterministically. That orchestration used to live only in the scanner; this
extracts it so all three share ONE implementation — and each command inherits its Ctrl-C safety,
submission-order guarantee, and single-writer progress for free.

What stays with the caller (deliberately): the work function, how a finished result becomes a
board tag/detail (`describe`), and how the returned outcomes map onto the command's own result
type and exit code. This module owns only the shared mechanism, never a command's policy.
"""
from __future__ import annotations

import sys
from typing import Any, Callable, Iterable, TextIO

from stayawake.utils import parallel
from stayawake.utils.parallel import Outcome
from stayawake.utils.progress import make_progress
from stayawake.utils.terminal import supports_color


def run_sweep(work_fn: Callable[[Any], Any], items: Iterable[Any], *, jobs: int, backend: str,
              labels: list[str], describe: Callable[[Outcome], tuple[str, str]],
              progress_on: bool, out: TextIO | None = None,
              verb: str = "Scanning") -> list[Outcome]:
    """Map `work_fn` over `items`, up to `jobs` at a time, driving a live board and returning
    `Outcome`s in SUBMISSION order (so a caller renders identically at any worker count).

    - `labels[i]` names item i on the board.
    - `describe(outcome)` renders ONE finished (non-error) item for the board. It returns either
      `(tag, detail)` — a compact completion line, e.g. `("[clean   ]", "12 findings")` — or
      `(tag, detail, block)`, where `block` is the caller's OWN fully-rendered multi-line result
      (a guard status block, …) printed under the header as the item scrolls up. So a command
      renders its result AT completion, in place and labelled — never in a separate untrackable
      pass. Called on the calling thread only, so it needs no locking.
    - `progress_on` picks a live board (a real TTY) vs one plain line per item (pipe / CI /
      `--no-stream`). The board draws on `out` (default stderr — progress, never the report).
    - `verb` is the board header's action word ("Fixing"/"Checking"…), cosmetic only.
    - A failed item never raises: it comes back as an `Outcome.error`, shows on the board as an
      `[ERROR]` line, and is returned so the caller can fail closed. Ctrl-C tears down in-flight
      workers immediately (see `parallel`).
    """
    out = out or sys.stderr
    work = list(items)
    progress = make_progress(enabled=progress_on, out=out, color=supports_color(out), verb=verb)
    progress.start(len(work))

    def on_start(index: int, _item: Any) -> None:
        progress.item_started(labels[index])

    def on_done(outcome: Outcome) -> None:
        if outcome.error:
            progress.item_done(labels[outcome.index], "[ERROR   ]", outcome.error)
        else:
            rendered = describe(outcome)
            tag, detail = rendered[0], rendered[1]
            block = rendered[2] if len(rendered) > 2 else None
            progress.item_done(labels[outcome.index], tag, detail, block=block)

    try:
        return parallel.run_ordered(work_fn, work, jobs=jobs, backend=backend,
                                    on_start=on_start, on_done=on_done)
    finally:
        progress.finish()
