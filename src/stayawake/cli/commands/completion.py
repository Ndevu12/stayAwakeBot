#!/usr/bin/env python3
"""`saw completion {bash,zsh,fish}` — emit a shell-completion script for `saw`/`stayawake`."""
from __future__ import annotations

import argparse

from stayawake.cli._meta import VERBS


def register(sub) -> None:
    p = sub.add_parser("completion", aliases=["comp"], help="emit a shell-completion script")
    p.add_argument("shell", choices=["bash", "zsh", "fish"])
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    verbs = " ".join(VERBS)
    if a.shell == "bash":
        print(
            '# saw bash completion — `eval "$(saw completion bash)"` or save to a '
            "completion dir\n"
            "_saw_completion() {\n"
            '  local cur="${COMP_WORDS[COMP_CWORD]}"\n'
            '  if [ "$COMP_CWORD" -eq 1 ]; then\n'
            f'    COMPREPLY=( $(compgen -W "{verbs}" -- "$cur") )\n'
            "  fi\n"
            "}\n"
            "complete -F _saw_completion saw stayawake"
        )
    elif a.shell == "zsh":
        print(
            "#compdef saw stayawake\n"
            "# saw zsh completion — save as _saw somewhere on your $fpath\n"
            "_saw() {\n"
            f"  local -a verbs; verbs=({verbs})\n"
            "  _arguments '1: :->cmd' '*::arg:->args'\n"
            "  [[ $state == cmd ]] && _describe 'command' verbs\n"
            "}\n"
            '_saw "$@"'
        )
    else:  # fish
        for binary in ("saw", "stayawake"):
            for v in VERBS:
                print(f"complete -c {binary} -n '__fish_use_subcommand' -a {v}")
    return 0
