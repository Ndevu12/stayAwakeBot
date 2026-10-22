#!/usr/bin/env python3
"""`saw capabilities` — what this saw supports, for a program that runs it."""
from __future__ import annotations

import argparse
import json
import sys

from stayawake.cli._meta import __version__
from stayawake.cli.argtypes import no_stream_requested
from stayawake.cli.helptext import add_command
from stayawake.utils import exitcodes
from stayawake.utils.host import saw_runs_here
from stayawake.utils.json_documents import SCHEMA_VERSION_OF_EACH_DOCUMENT, command_of, versioned
from stayawake.utils.streaming import say


def register(sub) -> None:
    p = add_command(
        sub, "capabilities",
        help="what this saw supports, for tools that run it",
        description=(
            "Print this saw's version, the schema version of each JSON document it prints, and "
            "the features it has. A program that runs saw reads this instead of comparing "
            "version numbers. Offline and read-only."),
        examples=[
            ("saw capabilities --json", "for a program to read"),
            ("saw capabilities", "the same, for a person"),
        ])
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=lambda a: run(a, sub.choices))


def _names_json(text: str) -> bool:
    """Say whether `text` names JSON output. A progress choice of `jsonl` does not."""
    return "json" in text.replace("jsonl", "")


def asks_for_json(parser: argparse.ArgumentParser) -> bool:
    """Say whether `parser` can ask for JSON output. Takes a command's parser. Returns whether one
    of its options names JSON, by its flag, its destination or one of its choices."""
    return any(_names_json(action.dest or "")
               or any(_names_json(option) for option in action.option_strings)
               or any(_names_json(str(choice)) for choice in (action.choices or ())
                      if not isinstance(action, argparse._SubParsersAction))
               for action in parser._actions)


def _takes_progress(parser: argparse.ArgumentParser) -> bool:
    """Say whether `parser` takes `--progress`. Returns the answer."""
    return any("--progress" in action.option_strings for action in parser._actions)


def offers_progress(commands: dict[str, argparse.ArgumentParser]) -> bool:
    """Say whether scan, audit or fix write progress events. Takes the top-level commands by name.
    Returns whether one of them takes `--progress`."""
    return any(_takes_progress(parser) for name in ("scan", "audit", "fix")
               if (parser := commands.get(name)) is not None)


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    """The subcommands `parser` offers, by name. Returns an empty mapping when it has none."""
    return next((action.choices for action in parser._actions
                 if isinstance(action, argparse._SubParsersAction)), {})


def prints_json(commands: dict[str, argparse.ArgumentParser], document: str) -> bool:
    """Say whether the command that prints `document` accepts JSON output.

    Takes the top-level commands by name. Returns False when the command does not exist."""
    parser = None
    for word in command_of(document):
        parser = commands.get(word)
        if parser is None:
            return False
        commands = _subcommands(parser)
    return parser is not None and asks_for_json(parser)


def capabilities(commands: dict[str, argparse.ArgumentParser]) -> dict:
    """Describe what this saw supports. Takes the top-level commands by name. Returns the version,
    each JSON document's schema version, the features and the platform."""
    documents = {document: version for document, version in SCHEMA_VERSION_OF_EACH_DOCUMENT.items()
                 if prints_json(commands, document)}
    features = [".".join(command_of(document)) + ".json" for document in documents]
    if offers_progress(commands):
        features.append("progress.jsonl")
    return versioned("capabilities", {
        "version": __version__,
        "schema_versions": documents,
        "features": features,
        "platform": {"os": sys.platform, "supported": saw_runs_here()},
    })


def run(a: argparse.Namespace, commands: dict[str, argparse.ArgumentParser]) -> int:
    held = capabilities(commands)
    if a.json:
        print(json.dumps(held, indent=2))
        return exitcodes.CLEAN
    lines = [f"saw {held['version']} on {held['platform']['os']}"
             + ("" if held["platform"]["supported"] else " (not supported)"),
             "JSON documents and their schema versions:"]
    lines += [f"  {document:<14}{version}" for document, version in held["schema_versions"].items()]
    lines.append("Features: " + ", ".join(held["features"]))
    say("\n".join(lines), no_stream=no_stream_requested(a))
    return exitcodes.CLEAN
