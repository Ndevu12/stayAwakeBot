#!/usr/bin/env python3
"""One home for how a command's `-h` reads: what it is for, then real invocations.

Every command parser is built through `add_command` rather than calling `add_parser`
directly, so no command can ship a bare flag list: `description` (the purpose, incl. the
safety-relevant fact) and `examples` are required arguments. The examples are the ones from
docs/CLI.md — the terminal and the guide show the same commands.

argparse reflows the epilog unless the parser opts into a raw formatter, and the stock raw
formatter freezes the description too (forcing hand-wrapped prose that ignores the terminal
width). `CommandHelpFormatter` splits the difference: prose wraps, examples stay verbatim.
"""
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
                examples: Sequence[tuple[str, str]], **kwargs) -> argparse.ArgumentParser:
    """Add a subparser that states its purpose and shows how it is actually invoked.

    `help` is the one-liner in the parent's command list; `description` is the paragraph at the
    top of this command's own `-h`; `examples` become the trailing `examples:` section.
    """
    return sub.add_parser(name, help=help, description=description,
                          epilog=examples_block(examples),
                          formatter_class=CommandHelpFormatter, **kwargs)
