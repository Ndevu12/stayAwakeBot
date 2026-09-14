#!/usr/bin/env python3
"""One home for how a command's `-h` reads: what it is for, then real invocations."""
from __future__ import annotations

import argparse
from collections.abc import Sequence


class _Verbatim(str):
    """An epilog whose line breaks and column alignment must survive help rendering."""


class CommandHelpFormatter(argparse.HelpFormatter):
    """Wrap the description to the terminal; print a `_Verbatim` epilog exactly as built."""

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        if isinstance(text, _Verbatim):
            return "".join(indent + line for line in text.splitlines(keepends=True))
        return super()._fill_text(text, width, indent)


def examples_block(examples: Sequence[tuple[str, str]]) -> _Verbatim:
    """Render `(invocation, why you'd run it)` pairs as an aligned `examples:` section.

    Alignment is computed here so no caller hand-pads a `#` comment into place (which drifts
    the moment an invocation is edited). Pass an empty note for a self-explanatory line.
    """
    column = max(len(invocation) for invocation, _ in examples)
    lines = [f"  {invocation.ljust(column)}   # {note}" if note else f"  {invocation}"
             for invocation, note in examples]
    return _Verbatim("examples:\n" + "\n".join(lines))


def add_command(sub, name: str, *, help: str, description: str,
                examples: Sequence[tuple[str, str]], stream: bool = True,
                **kwargs) -> argparse.ArgumentParser:
    """Add a subparser that states its purpose and shows how it is actually invoked.

    `help` is the one-liner in the parent's command list; `description` is the paragraph at the
    top of this command's own `-h`; `examples` become the trailing `examples:` section.
    Every command that produces a human report takes `--no-stream`. Pass `stream=False` ONLY on a
    parent whose own handler just prints help — a parent that renders a report (`saw auth`) needs
    the flag like any other command, and `tests/test_cli.py` derives that check from this tree
    rather than from a list.
    """
    from stayawake.cli.argtypes import add_no_stream_arg

    p = sub.add_parser(name, help=help, description=description,
                       epilog=examples_block(examples),
                       formatter_class=CommandHelpFormatter, **kwargs)
    declare_streaming(p, stream)
    if stream:
        add_no_stream_arg(p)
    return p


def declare_streaming(parser: argparse.ArgumentParser, streams: bool) -> None:
    """Record whether this command renders live output, so the flag it carries and the intent
    behind it cannot drift. A parser built by hand rather than through `add_command` declares it
    here; one that declares nothing fails the check in `tests/test_cli.py`."""
    parser.saw_streams = streams
