#!/usr/bin/env bash
# Shared worm-detection used by the StayAwakeBot git hooks (pre-commit, post-merge,
# post-checkout). Dependency-free (grep only) so it runs on any developer machine
# without the Python package installed. One responsibility: flag worm indicators in
# a given list of files.
#
# The fingerprint patterns are written escaped so this library never matches its own
# signatures (the full data-driven scanner lives in the stayawake package).

WORM_SIG='fromCharCode\(127\)|_\$_1e42|sfL\(|var _\$_|global\[_\$_'

# worm_scan_files <file>...  → prints one line per indicator, returns 1 if any found.
worm_scan_files() {
  local fail=0 f base
  for f in "$@"; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    grep -qIE "$WORM_SIG" "$f" 2>/dev/null && { echo "  ✗ worm loader fingerprint: $f"; fail=1; }
    [ "$base" = "fa-solid-400.woff2" ] && { echo "  ✗ suspicious payload font: $f"; fail=1; }
    case "$f" in
      *.vscode/tasks.json)
        grep -qE 'folderOpen' "$f" 2>/dev/null && grep -qE '\.woff2|node ' "$f" 2>/dev/null \
          && { echo "  ✗ VS Code folderOpen auto-run task: $f"; fail=1; } ;;
      *.vscode/settings.json)
        grep -q 'allowAutomaticTasks' "$f" 2>/dev/null \
          && { echo "  ✗ task.allowAutomaticTasks: $f"; fail=1; } ;;
    esac
    [ "$base" = ".gitignore" ] && grep -qE 'temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json' "$f" 2>/dev/null \
      && { echo "  ✗ worm .gitignore markers: $f"; fail=1; }
  done
  return $fail
}
