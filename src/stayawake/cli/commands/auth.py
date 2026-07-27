#!/usr/bin/env python3
"""`saw auth` — credential status + operator-managed StayAwakeBot GitHub App registration."""
from __future__ import annotations

import argparse
import json
import os

from stayawake.core.identity import Intent, require, resolve_session
from stayawake.lib import github_app


def register(sub) -> None:
    p = sub.add_parser(
        "auth", aliases=["a"],
        help="show GitHub credential/capability status; register a StayAwakeBot GitHub App",
    )
    asub = p.add_subparsers(dest="auth_cmd", metavar="<auth-command>")

    st = asub.add_parser("status", help="show active credential + capability gate for key intents")
    st.add_argument("--json", action="store_true", help="machine-readable output")
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
    reg.set_defaults(func=_app_register)

    show = apsub.add_parser("show", help="show whether a local StayAwakeBot App config is present")
    show.set_defaults(func=_app_show)

    p.set_defaults(func=_auth_root)


def _auth_root(a: argparse.Namespace) -> int:
    if not getattr(a, "auth_cmd", None):
        return _status(a)
    print("usage: saw auth status | saw auth app register | saw auth app show", flush=True)
    return 2


def _app_readiness_lines() -> list[str]:
    """Explain App config vs mint readiness (PyJWT + installation)."""
    lines: list[str] = []
    if not github_app.is_configured():
        return lines
    cfg = github_app.load_config() or {}
    lines.append(f"  StayAwakeBot App config: {github_app.config_path()}")
    if cfg.get("slug") or cfg.get("name"):
        label = cfg.get("name") or cfg.get("slug")
        lines.append(f"    app: {label}" + (f" ({cfg['slug']})" if cfg.get("slug") and cfg.get("name") else ""))
    if not github_app.jwt_available():
        lines.append(f"    ✗ cannot mint tokens yet — {github_app.APP_EXTRA_HINT}")
    elif not (cfg.get("installation_id") or os.environ.get("GH_APP_INSTALLATION_ID")):
        from stayawake.lib.github_app_manifest import install_url
        lines.append("    ⚠ registered but not installed (or installation_id unknown)")
        lines.append(f"      → {install_url(cfg.get('slug'))}")
    else:
        lines.append("    ✓ ready to mint installation tokens")
    return lines


def _status(a: argparse.Namespace) -> int:
    sess = resolve_session()
    intents = (Intent.READ_REMOTE, Intent.OPEN_FIX_PR, Intent.OPEN_GUARD_PR)
    rows = []
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
        "app_jwt_available": github_app.jwt_available(),
        "intents": rows,
    }
    if getattr(a, "json", False):
        print(json.dumps(payload, indent=2))
        return 0 if sess.live or sess.token is None else 1

    if not sess.token:
        print("• no GitHub credential (public scans still work)")
        print("  → `gh auth login`  or  `saw auth app register`")
        for line in _app_readiness_lines():
            print(line)
        return 0
    who = sess.actor or sess.source or "?"
    print(f"{'✓' if sess.live else '✗'} credential: {sess.source} as {who}"
          + ("" if sess.live else f" — {sess.detail or 'not live'}"))
    if sess.scopes is not None:
        print(f"  classic scopes: {', '.join(sorted(sess.scopes)) or '(none)'}")
    elif sess.capabilities is not None:
        print(f"  capabilities: {', '.join(sorted(c.value for c in sess.capabilities))}")
    else:
        print("  capabilities: unknown (fine-grained PAT?) — delivery will classify push failures")
    for line in _app_readiness_lines():
        print(line)
    # If App is configured but we fell through to gh, make the reason obvious.
    if github_app.is_configured() and sess.source == "gh" and not github_app.jwt_available():
        print(f"  note: App credentials are present but inactive until {github_app.APP_EXTRA_HINT}")
    print("  intent gate:")
    for row in rows:
        mark = "✓" if row["allowed"] else "✗"
        print(f"    {mark} {row['intent']}")
        if not row["allowed"]:
            if row["missing"]:
                print(f"        missing: {', '.join(row['missing'])}")
            for u in row["upgrades"]:
                if u["command"]:
                    print(f"        → {u['command']}")
                elif u["detail"]:
                    print(f"        → {u['detail']}")
    # Exit 1 when guard PR would be denied (the critical fleet path).
    guard = next(r for r in rows if r["intent"] == Intent.OPEN_GUARD_PR.value)
    return 0 if guard["allowed"] or not sess.live else 1


def _app_show(_a: argparse.Namespace) -> int:
    cfg = github_app.load_config()
    if not cfg and not github_app.is_configured():
        print("• no StayAwakeBot GitHub App configured")
        print("  → `saw auth app register`")
        return 1
    if cfg:
        print(f"✓ local App config: {github_app.config_path()}")
        print(f"  app_id: {cfg.get('app_id')}")
        print(f"  name:   {cfg.get('name') or '(unknown)'}")
        print(f"  slug:   {cfg.get('slug') or '(unknown — install from GitHub App settings)'}")
        if not github_app.jwt_available():
            print(f"  ✗ minting blocked — {github_app.APP_EXTRA_HINT}")
        if cfg.get("installation_id"):
            print(f"  installation_id: {cfg['installation_id']}")
        else:
            from stayawake.lib.github_app_manifest import install_url
            print(f"  → install on an account/org: {install_url(cfg.get('slug'))}")
    else:
        print("✓ App configured via environment (GH_APP_*)")
        if not github_app.jwt_available():
            print(f"  ✗ minting blocked — {github_app.APP_EXTRA_HINT}")
    return 0


def _app_register(a: argparse.Namespace) -> int:
    from stayawake.lib import github_app_manifest as manifest
    if not github_app.jwt_available():
        print(f"• tip: install the App extra before or after register: {github_app.APP_EXTRA_HINT}")
        print("  (needed to mint installation tokens; registration itself does not require it)")
    try:
        print("Starting StayAwakeBot GitHub App registration…")
        print("  browser will: create App → install on your account/org → return here")
        payload = manifest.register_via_browser(
            name=getattr(a, "name", "StayAwakeBot") or "StayAwakeBot",
            open_browser=not getattr(a, "no_browser", False),
        )
    except github_app.GithubAppError as e:
        print(f"✗ {e}")
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"✗ registration failed: {e}")
        return 2
    slug = payload.get("slug")
    print(f"✓ registered App id={payload.get('id')} slug={slug}")
    print(f"  credentials saved to {github_app.config_path()} (mode 0600)")
    if payload.get("_installed") and payload.get("installation_id"):
        print(f"✓ installed (installation_id={payload['installation_id']})")
    else:
        print("⚠ App registered but install was not completed in this session")
        print(f"  → finish install: {payload.get('_install_url') or manifest.install_url(slug)}")
        print("  → then: saw auth status")
    icon = payload.get("_icon_path")
    settings = payload.get("_settings_url")
    if icon and settings:
        print("  branding: upload the StayAwakeBot icon in App settings → Display information")
        print(f"    icon: {icon}")
        print(f"    settings: {settings}")
    if not github_app.jwt_available():
        print(f"  next: {github_app.APP_EXTRA_HINT}")
        print("       then: saw auth status   # confirm open_guard_pr is allowed")
    else:
        print("  next: saw auth status   # confirm open_guard_pr is allowed")
    print("  note: this App is operator-managed — you own the registration and credentials.")
    return 0 if payload.get("_installed") else 1
