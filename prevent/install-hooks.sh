#!/usr/bin/env bash
# Install the worm pre-commit hook into the current git repo.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
src="$(cd "$(dirname "$0")" && pwd)/pre-commit"
dst="$root/.git/hooks/pre-commit"
cp "$src" "$dst" && chmod +x "$dst"
echo "Installed worm pre-commit hook → $dst"
