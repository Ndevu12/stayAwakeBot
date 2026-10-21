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


def prints_json(commands: dict[str, argparse.ArgumentParser], document: str) -> bool:
    """Say whether the command that prints `document` accepts `--json`.

    Takes the top-level commands by name. Returns False when the command does not exist."""
    parser = None
    for word in command_of(document):
        parser = commands.get(word)
        if parser is None:
            return False
        commands = next((action.choices for action in parser._actions
                         if isinstance(action, argparse._SubParsersAction)), {})
    return any("--json" in action.option_strings for action in parser._actions)


def capabilities(commands: dict[str, argparse.ArgumentParser]) -> dict:
    """Describe what this saw supports. Takes the top-level commands by name. Returns the version,
    each JSON document's schema version, the features and the platform."""
    documents = {document: version for document, version in SCHEMA_VERSION_OF_EACH_DOCUMENT.items()
                 if prints_json(commands, document)}
    return versioned("capabilities", {
        "version": __version__,
        "schema_versions": documents,
        "features": [".".join(command_of(document)) + ".json" for document in documents],
        "platform": {"os": sys.platform, "supported": not sys.platform.startswith("win")},
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
