#!/usr/bin/env bash
# Install the StayAwakeBot worm hooks for defense-in-depth on a developer machine.
# Installs three layers: pre-commit (outgoing), post-merge + post-checkout (incoming).
#
#   install-hooks.sh                  # this repo only (.git/hooks)
#   install-hooks.sh --template       # all FUTURE clones (git init.templateDir)
#   install-hooks.sh --all <root>...  # every existing repo found under the given roots
#   install-hooks.sh --force ...      # overwrite a foreign hook instead of backing it up
#   install-hooks.sh --help
set -euo pipefail

HOOKS=(pre-commit post-merge post-checkout)
src_dir="$(cd "$(dirname "$0")/hooks" && pwd)"

# Split out --force; keep the remaining positional args.
FORCE=0
args=()
for a in "$@"; do
  if [ "$a" = "--force" ]; then FORCE=1; else args+=("$a"); fi
done
set -- ${args[@]+"${args[@]}"}

install_into() {                       # install_into <hooks-dir>
  local dst="$1" h existing
  mkdir -p "$dst"
  cp "$src_dir/_worm_lib.sh" "$dst/_worm_lib.sh"
  for h in "${HOOKS[@]}"; do
    existing="$dst/$h"
    # Never silently destroy a developer's own hook (Husky, secret-scanners, …).
    if [ -e "$existing" ] && ! grep -q "StayAwakeBot" "$existing" 2>/dev/null; then
      if [ "$FORCE" != 1 ] && [ ! -e "$existing.pre-stayawake.bak" ]; then
        cp "$existing" "$existing.pre-stayawake.bak"
        echo "  ⚠ backed up existing $h → $h.pre-stayawake.bak (chained run not configured; --force to skip)"
      fi
    fi
    cp "$src_dir/$h" "$existing"
    chmod +x "$existing"
  done
}

# Resolve a discovered `.git` (dir, or a 'gitdir:' file for submodules/worktrees) to
# its hooks dir.
hooks_dir_for() {
  local gitpath="$1" gd
  if [ -d "$gitpath" ]; then
    echo "$gitpath/hooks"
  elif [ -f "$gitpath" ]; then
    gd="$(sed -n 's/^gitdir: //p' "$gitpath" 2>/dev/null)"
    [ -n "$gd" ] || return 1
    case "$gd" in /*) : ;; *) gd="$(dirname "$gitpath")/$gd" ;; esac
    echo "$gd/hooks"
  else
    return 1
  fi
}

case "${1:-}" in
  --template)
    tdir="${HOME}/.config/git/template"
    install_into "$tdir/hooks"
    chmod 700 "$tdir" "$tdir/hooks"
    git config --global init.templateDir "$tdir"
    echo "Worm hooks registered for all FUTURE clones → $tdir/hooks"
    echo "(existing repos: run with --all <roots>, or once inside each repo)"
    ;;
  --all)
    shift
    [ "$#" -gt 0 ] || { echo "usage: install-hooks.sh --all <root>..." >&2; exit 2; }
    count=0
    for root in "$@"; do
      while IFS= read -r gitpath; do
        if hd="$(hooks_dir_for "$gitpath")"; then
          install_into "$hd"
          echo "  ✓ $(dirname "$gitpath")"
          count=$((count + 1))
        fi
      done < <(find "$root" \( -name node_modules -o -name .venv \) -prune \
                 -o \( -type d -o -type f \) -name .git -print 2>/dev/null)
    done
    echo "Installed worm hooks into $count repo(s)."
    echo "Note: bare repos (no .git dir/file) are not auto-detected — install into those manually."
    ;;
  --help | -h)
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    ;;
  "")
    root="$(git rev-parse --show-toplevel)"
    install_into "$root/.git/hooks"
    echo "Installed worm hooks (pre-commit, post-merge, post-checkout) → $root/.git/hooks"
    if [ -z "$(git config --global init.templateDir || true)" ]; then
      echo "⚠ Future clones are NOT protected yet. Run: $0 --template"
    fi
    ;;
  *)
    echo "unknown option: $1 (try --help)" >&2
    exit 2
    ;;
esac
