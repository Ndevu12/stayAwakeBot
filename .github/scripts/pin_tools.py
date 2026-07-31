#!/usr/bin/env python3
"""Scanner-pin tooling — the single source for the worm-guard pin invariants.

Consolidates what used to be four bash files (`_pin_lib.sh` + `check_pin_freshness.sh` +
`check_pins_synced.sh` + `check_pin_drift.sh`) into one Python module, so "what is the detection
engine", "how the pin is written", and "which files carry it" are defined exactly ONCE (DRY).

Subcommands — run as `python3 .github/scripts/pin_tools.py <cmd>`:
  freshness <changed-files> <unified-diff>   in-band PR gate: engine changed ⇒ the pin must be
                                             bumped (env DEFERRED=yes acknowledges a deliberate defer)
  synced [file ...]                          in-band gate: every pin carrier holds the SAME SHA
                                             (defaults to PIN_FILES)
  drift                                      out-of-band backstop: open/comment/close a tracking
                                             issue when the pinned engine falls behind main (uses gh)

The pure decision functions (`extract_pin`, `is_engine_changed`, `is_pin_bumped`, `freshness`,
`pins_synced`) are importable and unit-tested in tests/test_pin_tooling.py; `drift` is thin
git/gh subprocess glue. GitHub workflow commands (`::error::` / `::notice::` / `::warning::`) are
printed to stdout, where the Actions runner parses them into annotations.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ── single source of truth ───────────────────────────────────────────────────────────────────────
# The detection-engine subtree. Engine ONLY — so report/signature-doc commits never count as drift,
# and a PR that touches only tests/docs never demands a pin bump. This is the seam the pin tracks.
ENGINE_SUBTREE = "src/stayawake/bots/security"
# The gate whose pinned scanner the drift backstop compares against main.
GUARD_FILE = ".github/workflows/worm-guard.yml"
# The release self-scan carries a SECOND, independent copy of the pin. It must stay identical to the
# guard pin or the release gate silently scans a different engine — the drift `synced` prevents. Add
# any further pin carrier to PIN_FILES.
RELEASE_FILE = ".github/workflows/release.yml"
PIN_FILES = [GUARD_FILE, RELEASE_FILE]
# The pin token: `sentinel-ref: <40-hex SHA>`. A 40-char SHA is REQUIRED — a floating ref
# (`sentinel-ref: main`) violates the pin doctrine and must NEVER read as a valid pin.
_PIN_RE = re.compile(r"sentinel-ref:\s*([0-9a-f]{40})")
# An ADDED (+) pin line carrying a 40-char SHA = a deliberate bump (a floating ref doesn't count).
_ADDED_PIN_RE = re.compile(r"^\+\s*sentinel-ref:\s*[0-9a-f]{40}")


def extract_pin(text: str) -> str | None:
    """The first 40-hex sentinel-ref SHA in `text`, or None (none present / a floating ref)."""
    m = _PIN_RE.search(text)
    return m.group(1) if m else None


def extract_pin_file(path: str | Path) -> str | None:
    try:
        return extract_pin(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return None


# ── freshness: engine changed ⇒ pin bumped (or deferred) ──────────────────────────────────────────
def is_engine_changed(changed_paths: list[str]) -> bool:
    """True if any changed path is under the engine subtree. Anchored with a trailing slash so a
    sibling like `.../security_helpers/` — or `tests/bots/security/` — does not match."""
    prefix = ENGINE_SUBTREE + "/"
    return any(p.startswith(prefix) for p in changed_paths)


def is_pin_bumped(diff_text: str) -> bool:
    """True if the unified diff ADDS a `sentinel-ref` line with a 40-hex SHA. A pin line present only
    as unchanged context (no leading '+'), or reset to a floating ref, does NOT count as a bump."""
    return any(_ADDED_PIN_RE.match(line) for line in diff_text.splitlines())


def freshness(changed_text: str, diff_text: str, deferred: bool) -> tuple[int, str]:
    """Decide the in-band gate from a PR's changed-file list and unified diff. Returns (exit, msg)."""
    changed = [l.strip() for l in changed_text.splitlines() if l.strip()]
    if not is_engine_changed(changed):
        return 0, "Pin freshness: PR does not touch the detection engine — nothing to enforce."
    if is_pin_bumped(diff_text):
        return 0, "Pin freshness: engine changed and sentinel-ref was bumped in this PR — OK."
    if deferred:
        return 0, ("::notice::Pin freshness: the engine changed and the pin was NOT bumped, but this "
                   "PR is labeled 'pin-bump-deferred' — deferral acknowledged. Remember to bump "
                   "sentinel-ref before or at the end of this line of work.")
    return 1, ("::error::This PR changes the detection engine (src/stayawake/bots/security/**) but "
               "does not bump 'sentinel-ref' in .github/workflows/worm-guard.yml — the worm-guard "
               "gate would keep scanning with the OLD pinned engine. Fix: bump sentinel-ref to a "
               "current reviewed main SHA in this PR, or add the 'pin-bump-deferred' label to defer "
               "the bump deliberately (e.g. one bump at the end of an epic).")


# ── synced: every carrier holds the same SHA ──────────────────────────────────────────────────────
def pins_synced(pins: dict[str, str | None]) -> tuple[int, list[str]]:
    """`pins` maps each carrier file to its extracted SHA (or None). Fails if any pin is
    missing/floating, or the pins disagree. Returns (exit, messages)."""
    status, ref, ref_file, msgs = 0, None, None, []
    for f, pin in pins.items():
        if not pin:
            msgs.append(f"::error::no 40-char sentinel-ref SHA in {f} — a floating ref "
                        f"('sentinel-ref: main') is not a valid pin. Every pin carrier must hold the "
                        f"same reviewed main SHA.")
            status = 1
            continue
        if ref is None:
            ref, ref_file = pin, f
        elif pin != ref:
            msgs.append(f"::error::scanner pin mismatch — {ref_file} pins {ref} but {f} pins {pin}. "
                        f"Bump BOTH to the same reviewed main SHA (the worm-guard gate and the "
                        f"release self-scan must scan with the same engine).")
            status = 1
    if status == 0:
        msgs.append(f"Scanner pins in sync: {ref} across {len(pins)} file(s).")
    return status, msgs


# ── drift: out-of-band backstop (git + gh glue) ───────────────────────────────────────────────────
_DRIFT_TITLE = "worm-guard scanner pin is behind main"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def _find_drift_issue() -> str | None:
    r = _run(["gh", "issue", "list", "--state", "open", "--search", f"{_DRIFT_TITLE} in:title",
              "--json", "number,title"])
    try:
        for item in json.loads(r.stdout or "[]"):
            if item.get("title") == _DRIFT_TITLE:
                return str(item["number"])
    except (json.JSONDecodeError, KeyError, TypeError):
        pass
    return None


def drift() -> int:
    """Compare the guard pin against the engine on HEAD; open/comment/close a tracking issue. Exit 0
    on success (drift is reported as an issue, not a build failure); 1 if the pin is unreadable."""
    pin = extract_pin_file(GUARD_FILE)
    if not pin:
        print(f"::error::could not read a 40-char sentinel-ref SHA from {GUARD_FILE}")
        return 1
    print(f"Pinned scanner: {pin}")
    existing = _find_drift_issue()

    diff = _run(["git", "diff", "--quiet", pin, "HEAD", "--", ENGINE_SUBTREE])
    if diff.returncode not in (0, 1):
        print(f"::error::git diff failed comparing {pin}..HEAD ({diff.stderr.strip()})")
        return 1
    if diff.returncode == 0:
        print("Engine pin is current with main — no drift.")
        if existing:
            _run(["gh", "issue", "close", existing,
                  "--comment", "Engine pin is current again (resolved automatically)."])
        return 0

    print(f"::warning::engine has drifted from the pinned scanner ({pin})")
    names = _run(["git", "diff", "--name-only", pin, "HEAD", "--", ENGINE_SUBTREE]).stdout.split()
    changed = "\n".join(f"- {n}" for n in names)
    short = _run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    if existing:
        _run(["gh", "issue", "comment", existing, "--body", f"Still drifting as of {short}."])
    else:
        body = (
            f"The worm-guard gate pins `sentinel-ref: {pin}`, but the detection engine "
            f"(`{ENGINE_SUBTREE}/`) on `main` has changed since. **The gate is running an "
            f"out-of-date scanner.**\n\n"
            f"Bump `sentinel-ref` in `{GUARD_FILE}` to a current reviewed `main` SHA (after "
            f"confirming the change is intended), then merge.\n\n"
            f"Engine files changed since the pin:\n{changed}\n\n"
            f"_Auto-opened by the `scanner-pin-drift` workflow; it closes itself when the pin "
            f"catches up._")
        _run(["gh", "issue", "create", "--title", _DRIFT_TITLE, "--body", body])
    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────────────────────────
def _cmd_freshness(args: argparse.Namespace) -> int:
    changed = Path(args.changed_files).read_text(encoding="utf-8")
    diff = Path(args.unified_diff).read_text(encoding="utf-8")
    code, msg = freshness(changed, diff, os.environ.get("DEFERRED", "no") == "yes")
    print(msg)
    return code


def _cmd_synced(args: argparse.Namespace) -> int:
    files = args.files or PIN_FILES
    code, msgs = pins_synced({f: extract_pin_file(f) for f in files})
    for m in msgs:
        print(m)
    return code


def _cmd_drift(_args: argparse.Namespace) -> int:
    return drift()


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Worm-guard scanner-pin invariants.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("freshness", help="in-band: engine changed ⇒ pin must be bumped")
    f.add_argument("changed_files", help="file with one changed path per line (gh pr diff --name-only)")
    f.add_argument("unified_diff", help="file with the PR's unified diff (gh pr diff)")
    f.set_defaults(fn=_cmd_freshness)
    s = sub.add_parser("synced", help="in-band: every pin carrier holds the same SHA")
    s.add_argument("files", nargs="*", help="pin files to compare (default: PIN_FILES)")
    s.set_defaults(fn=_cmd_synced)
    d = sub.add_parser("drift", help="out-of-band: open/close an issue when the pin lags main")
    d.set_defaults(fn=_cmd_drift)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
