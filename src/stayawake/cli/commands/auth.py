#!/usr/bin/env python3
"""`saw auth` — credential status + operator-managed StayAwakeBot GitHub App registration."""
from __future__ import annotations

import argparse
import json
import sys

from stayawake.core.identity import Intent, require, resolve_session
from stayawake.lib import github_app
from stayawake.utils import env
from stayawake.utils.streaming import Streamer, status, stream_enabled


def register(sub) -> None:
    p = sub.add_parser(
        "auth", aliases=["a"],
        help="show GitHub credential/capability status; register a StayAwakeBot GitHub App",
    )
    asub = p.add_subparsers(dest="auth_cmd", metavar="<auth-command>")

    st = asub.add_parser("status", help="show active credential + capability gate for key intents")
    st.add_argument("--json", action="store_true", help="machine-readable output")
    st.add_argument("--no-stream", action="store_true", help="disable animated output")
    st.set_defaults(func=_status)

    ap = asub.add_parser(
        "app", help="manage the operator-managed StayAwakeBot GitHub App",
    )
    apsub = ap.add_subparsers(dest="app_cmd", metavar="<app-command>")

    reg = apsub.add_parser(
        "register",
        help="register + install a StayAwakeBot App via GitHub's manifest flow "
             "(stores credentials locally)",
    )
    reg.add_argument("--name", default="StayAwakeBot",
                     help="App display name (default: StayAwakeBot)")
    reg.add_argument("--no-browser", action="store_true",
                     help="print the local URL instead of opening a browser")
    reg.add_argument("--replace", action="store_true",
                     help="register a brand-new App even if one is already configured locally "
                          "(otherwise register is a no-op that points you at installing the existing "
                          "App on more accounts/orgs)")
    reg.add_argument("--no-stream", action="store_true", help="disable animated output")
    reg.set_defaults(func=_app_register)

    show = apsub.add_parser("show", help="show whether a local StayAwakeBot App config is present")
    show.add_argument("--no-stream", action="store_true", help="disable animated output")
    show.set_defaults(func=_app_show)

    p.set_defaults(func=_auth_root)


def _streamer(a: argparse.Namespace) -> Streamer:
    """A stdout Streamer honoring `--no-stream` (and auto-off when piped / CI / non-TTY)."""
    return Streamer(enabled=stream_enabled(sys.stdout, force_off=getattr(a, "no_stream", False)))


def _auth_root(a: argparse.Namespace) -> int:
    if not getattr(a, "auth_cmd", None):
        return _status(a)
    print("usage: saw auth status | saw auth app register | saw auth app show", flush=True)
    return 2


def _app_readiness_lines() -> list[str]:
    """Explain App config vs mint readiness. Signing is BUILT IN (no crypto extra), so once the App is
    configured the only remaining step is completing the installation."""
    lines: list[str] = []
    if not github_app.is_configured():
        return lines
    cfg = github_app.load_config() or {}
    lines.append(f"  StayAwakeBot App config: {github_app.config_path()}")
    if cfg.get("slug") or cfg.get("name"):
        label = cfg.get("name") or cfg.get("slug")
        lines.append(f"    app: {label}" + (f" ({cfg['slug']})" if cfg.get("slug") and cfg.get("name") else ""))
    if not (cfg.get("installation_id") or env.get(github_app.INSTALLATION_ID_ENV)):
        from stayawake.lib.github_app_manifest import install_url
        lines.append("    ⚠ registered but not installed (or installation_id unknown)")
        lines.append(f"      → {install_url(cfg.get('slug'))}")
    else:
        lines.append("    ✓ ready to mint installation tokens")
    return lines


def _status(a: argparse.Namespace) -> int:
    prog = _streamer(a)
    intents = (Intent.READ_REMOTE, Intent.OPEN_FIX_PR, Intent.OPEN_GUARD_PR)
    rows = []
    # The gate probes GitHub for liveness/capabilities — cover the silent wait with a spinner
    # (stderr; never pollutes the --json stdout). Keep the label neutral: a security tool must not
    # imply it is transmitting or "resolving" the user's secret — it's only checking access.
    with status("checking GitHub access…", enabled=prog.enabled):
        sess = resolve_session()
        for intent in intents:
            d = require(intent, session=sess)
            rows.append({
                "intent": intent.value,
                "allowed": d.allowed,
                "missing": sorted(c.value for c in d.missing),
                "reason": d.reason if not d.allowed else "",
                "upgrades": [
                    {"kind": u.kind, "detail": u.detail, "command": u.command}
                    for u in d.upgrades
                ],
            })
    payload = {
        "source": sess.source,
        "kind": sess.kind,
        "actor": sess.actor,
        "live": sess.live,
        "scopes": sorted(sess.scopes) if sess.scopes is not None else None,
        "capabilities": (sorted(c.value for c in sess.capabilities)
                         if sess.capabilities is not None else None),
        "app_configured": github_app.is_configured(),
        "intents": rows,
    }
    if getattr(a, "json", False):
        print(json.dumps(payload, indent=2))
        return 0 if sess.live or sess.token is None else 1

    if not sess.token:
        prog.line("• no GitHub credential (public scans still work)")
        prog.line("  → `gh auth login`  or  `saw auth app register`")
        for line in _app_readiness_lines():
            prog.line(line)
        return 0
    who = sess.actor or sess.source or "?"
    prog.line(f"{'✓' if sess.live else '✗'} credential: {sess.source} as {who}"
              + ("" if sess.live else f" — {sess.detail or 'not live'}"))
    if sess.scopes is not None:
        prog.line(f"  classic scopes: {', '.join(sorted(sess.scopes)) or '(none)'}")
    elif sess.capabilities is not None:
        prog.line(f"  capabilities: {', '.join(sorted(c.value for c in sess.capabilities))}")
    else:
        prog.line("  capabilities: unknown (fine-grained PAT?) — delivery will classify push failures")
    for line in _app_readiness_lines():
        prog.line(line)
    prog.line("  intent gate:")
    for row in rows:
        mark = "✓" if row["allowed"] else "✗"
        prog.line(f"    {mark} {row['intent']}")
        if not row["allowed"]:
            if row["missing"]:
                prog.line(f"        missing: {', '.join(row['missing'])}")
            for u in row["upgrades"]:
                if u["command"]:
                    prog.line(f"        → {u['command']}")
                elif u["detail"]:
                    prog.line(f"        → {u['detail']}")
    # Exit 1 when guard PR would be denied (the critical fleet path).
    guard = next(r for r in rows if r["intent"] == Intent.OPEN_GUARD_PR.value)
    return 0 if guard["allowed"] or not sess.live else 1


def _app_show(a: argparse.Namespace) -> int:
    prog = _streamer(a)
    cfg = github_app.load_config()
    if not cfg and not github_app.is_configured():
        prog.line("• no StayAwakeBot GitHub App configured")
        prog.line("  → `saw auth app register`")
        return 1
    if cfg:
        from stayawake.lib.github_app_manifest import install_url, settings_url
        slug = cfg.get("slug")
        prog.line(f"✓ local App config: {github_app.config_path()}")
        prog.line(f"  app_id: {cfg.get('app_id')}")
        prog.line(f"  name:   {cfg.get('name') or '(unknown)'}")
        prog.line(f"  slug:   {slug or '(unknown — install from GitHub App settings)'}")
        if cfg.get("installation_id"):
            prog.line(f"  installation_id: {cfg['installation_id']}")
        prog.line("  install on more accounts/orgs (a GitHub App is per-account):")
        prog.line(f"    → {install_url(slug)}")
        prog.line("  if the install page offers no account picker, the App is set to 'Only on this")
        prog.line("  account' — switch it to 'Any account' in App settings, then install:")
        prog.line(f"    → {settings_url(slug, app_id=cfg.get('app_id'))}")
    else:
        prog.line("✓ App configured via environment (GH_APP_*)")
    return 0


def _already_registered(prog: Streamer, a: argparse.Namespace) -> int | None:
    """If a StayAwakeBot App is ALREADY configured locally, don't create a duplicate — GitHub App
    names are globally unique, so a fresh manifest run mints a NEW App with a suffixed name every
    time (the reported duplication). Confirm the App still exists on GitHub, then point the operator
    at the real next step — INSTALLING the same App on more accounts/orgs — and return 0. Returns None
    (→ proceed to register) only when nothing is configured, `--replace` is set, or the previously
    registered App is confirmed GONE from GitHub."""
    if getattr(a, "replace", False) or not github_app.is_configured():
        return None
    from stayawake.lib.github_app_manifest import install_url, settings_url
    cfg = github_app.load_config() or {}
    slug = cfg.get("slug")
    with status("checking your existing StayAwakeBot App on GitHub…", enabled=prog.enabled):
        exists = github_app.app_exists()
    if exists is False:
        prog.line("⚠ the previously registered StayAwakeBot App no longer exists on GitHub — "
                  "registering a new one.")
        return None
    label = cfg.get("name") or slug or f"app_id={cfg.get('app_id')}"
    suffix = f" ({slug})" if slug and cfg.get("name") else ""
    prog.line(f"✓ a StayAwakeBot App is already registered on GitHub: {label}{suffix}")
    if exists is None:
        prog.line("  (couldn't confirm it still exists on GitHub — offline, rate-limited, or a "
                  "key/clock issue — so not creating a duplicate; use --replace to force a new App)")
    prog.line(f"  local config: {github_app.config_path()}")
    prog.line("  Note: this is the App REGISTRATION — it stays even after you UNINSTALL the App "
              "(uninstalling only removes an installation, not the registration).")
    prog.line("  What you probably want:")
    prog.line("  • run it on another account/org — install this SAME App there (a GitHub App is")
    prog.line(f"    per-account, so each org needs its own installation): {install_url(slug)}")
    prog.line("    (no account picker there? the App is 'Only on this account' — set it to "
              f"'Any account' first: {settings_url(slug, app_id=cfg.get('app_id'))})")
    prog.line("  • start completely over — DELETE the registration, then register again:")
    prog.line(f"    {settings_url(slug, app_id=cfg.get('app_id'))} → Advanced → Delete GitHub App")
    prog.line("  • replace it now with a brand-new App:  saw auth app register --replace")
    return 0


def _app_register(a: argparse.Namespace) -> int:
    from stayawake.lib import github_app_manifest as manifest
    prog = _streamer(a)
    # Idempotency guard: never mint a duplicate App when one is already configured (the reported bug).
    early = _already_registered(prog, a)
    if early is not None:
        return early
    try:
        prog.line("Starting StayAwakeBot GitHub App registration…")
        prog.line("  a browser will open: create App → install on your account/org → return here")
        with status("waiting for GitHub (complete the flow in your browser)…", enabled=prog.enabled):
            payload = manifest.register_via_browser(
                name=getattr(a, "name", "StayAwakeBot") or "StayAwakeBot",
                open_browser=not getattr(a, "no_browser", False),
            )
    except github_app.GithubAppError as e:
        prog.line(f"✗ {e}")
        return 2
    except Exception as e:  # noqa: BLE001
        prog.line(f"✗ registration failed: {e}")
        return 2
    slug = payload.get("slug")
    prog.line(f"✓ registered App id={payload.get('id')} slug={slug}")
    prog.line(f"  credentials saved to {github_app.config_path()} (mode 0600)")
    if payload.get("_installed") and payload.get("installation_id"):
        prog.line(f"✓ installed (installation_id={payload['installation_id']})")
    else:
        prog.line("⚠ App registered but install was not completed in this session")
        prog.line(f"  → finish install: {payload.get('_install_url') or manifest.install_url(slug)}")
        prog.line("  → then: saw auth status")
    icon = payload.get("_icon_path")
    settings = payload.get("_settings_url")
    if icon and settings:
        prog.line("  branding: upload the StayAwakeBot icon in App settings → Display information")
        prog.line(f"    icon: {icon}")
        prog.line(f"    settings: {settings}")
    prog.line("  next: saw auth status   # confirm open_guard_pr is allowed")
    prog.line("  note: this App is operator-managed — you own the registration and credentials.")
    return 0 if payload.get("_installed") else 1
