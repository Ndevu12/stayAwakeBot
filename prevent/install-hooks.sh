#!/usr/bin/env bash
# Install the StayAwakeBot worm hooks for defense-in-depth on a developer machine.
# Installs three layers: pre-commit (outgoing), post-merge + post-checkout (incoming).
#
#   install-hooks.sh                  # this repo only (.git/hooks)
#   install-hooks.sh --template       # all FUTURE clones (git init.templateDir)
#   install-hooks.sh --all <root>...  # every existing repo found under the given roots
#   install-hooks.sh --help
set -euo pipefail

HOOKS=(pre-commit post-merge post-checkout)
src_dir="$(cd "$(dirname "$0")/hooks" && pwd)"

install_into() {                       # install_into <hooks-dir>
  local dst="$1" h
  mkdir -p "$dst"
  cp "$src_dir/_worm_lib.sh" "$dst/_worm_lib.sh"
  for h in "${HOOKS[@]}"; do
    cp "$src_dir/$h" "$dst/$h"
    chmod +x "$dst/$h"
  done
}

case "${1:-}" in
  --template)
    tdir="${HOME}/.config/git/template"
    install_into "$tdir/hooks"
    git config --global init.templateDir "$tdir"
    echo "Worm hooks registered for all FUTURE clones → $tdir/hooks"
    echo "(existing repos: run with --all <roots>, or once inside each repo)"
    ;;
  --all)
    shift
    [ "$#" -gt 0 ] || { echo "usage: install-hooks.sh --all <root>..." >&2; exit 2; }
    count=0
    for root in "$@"; do
      while IFS= read -r gitdir; do
        [ -d "$gitdir" ] || continue   # skip worktree .git files
        install_into "$gitdir/hooks"
        echo "  ✓ $(dirname "$gitdir")"
        count=$((count + 1))
      done < <(find "$root" -type d \( -name node_modules -o -name .venv \) -prune \
                 -o -type d -name .git -print 2>/dev/null)
    done
    echo "Installed worm hooks into $count repo(s)."
    ;;
  --help | -h)
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  "")
    root="$(git rev-parse --show-toplevel)"
    install_into "$root/.git/hooks"
    echo "Installed worm hooks (pre-commit, post-merge, post-checkout) → $root/.git/hooks"
    ;;
  *)
    echo "unknown option: $1 (try --help)" >&2
    exit 2
    ;;
esac
