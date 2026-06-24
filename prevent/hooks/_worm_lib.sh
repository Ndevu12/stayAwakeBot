#!/usr/bin/env bash
# Shared worm-detection used by the StayAwakeBot git hooks (pre-commit, post-merge,
# post-checkout). Dependency-free (grep only) so it runs on any developer machine
# without the Python package installed. One responsibility: flag worm indicators in
# a given list of files.
#
# The fingerprint patterns are written escaped so this library never matches its own
# signatures (the full data-driven scanner lives in the stayawake package).

# Loader fingerprints. The broad "global[" prefix catches the bang-bootstrap and the
# require-hijack variants. grep flags: -a scans NUL-laden "binary" source (so one NUL
# byte can't hide a payload), -i case-folds (sfL/SFL, 0x7f/0X7F).
WORM_SIG='fromCharCode\((127|0x7f)|_\$_1e42|sfL\(|(var|let|const) _\$_|global\['
BLOCKCHAIN_RE='Blockchain Explorer|BlockchainFont|TechMono'

# worm_scan_files <file>...  → prints one line per indicator, returns 1 if any found.
worm_scan_files() {
  local fail=0 f base
  for f in "$@"; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    grep -qaiE "$WORM_SIG" "$f" 2>/dev/null && { echo "  ✗ worm loader fingerprint: $f"; fail=1; }
    # Minified single-line payload (oversized line) in a source file.
    case "$f" in
      *.js|*.mjs|*.cjs|*.ts|*.tsx|*.jsx|*.mts|*.cts|*.vue)
        awk 'length>2000{f=1} END{exit !f}' "$f" 2>/dev/null \
          && { echo "  ✗ oversized minified line (possible payload): $f"; fail=1; } ;;
    esac
    # A "font" carrying text/JS is a disguised payload (not just the known name).
    case "$f" in
      *.woff2|*.woff|*.ttf|*.otf)
        grep -qaiE 'function|require\(|=>|fromCharCode|eval\(' "$f" 2>/dev/null \
          && { echo "  ✗ text/JS inside a font file: $f"; fail=1; } ;;
    esac
    [ "$base" = "fa-solid-400.woff2" ] && { echo "  ✗ suspicious payload font: $f"; fail=1; }
    case "$f" in
      *.vscode/tasks.json)
        grep -qE 'folderOpen' "$f" 2>/dev/null && grep -qE '\.woff2|node ' "$f" 2>/dev/null \
          && { echo "  ✗ VS Code folderOpen auto-run task: $f"; fail=1; } ;;
      *.vscode/settings.json)
        grep -q 'allowAutomaticTasks' "$f" 2>/dev/null \
          && { echo "  ✗ task.allowAutomaticTasks: $f"; fail=1; } ;;
      README.md|*/README.md)
        grep -qaiE "$BLOCKCHAIN_RE" "$f" 2>/dev/null \
          && { echo "  ✗ blockchain camouflage README: $f"; fail=1; } ;;
    esac
    [ "$base" = ".gitignore" ] && grep -qE 'temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json' "$f" 2>/dev/null \
      && { echo "  ✗ worm .gitignore markers: $f"; fail=1; }
  done
  return $fail
}
