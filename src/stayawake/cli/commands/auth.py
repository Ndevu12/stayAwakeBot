#!/usr/bin/env python3
"""`saw auth` — credential status + Phase 1 self-owned GitHub App registration."""
from __future__ import annotations

import argparse
import json

from stayawake.core.identity import Intent, require, resolve_session
from stayawake.lib import github_app


def register(sub) -> None:
    p = sub.add_parser(
        "auth", aliases=["a"],
        help="show GitHub credential/capability status; register a self-owned Saw App",
    )
    asub = p.add_subparsers(dest="auth_cmd", metavar="<auth-command>")

    st = asub.add_parser("status", help="show active credential + capability gate for key intents")
    st.add_argument("--json", action="store_true", help="machine-readable output")
    st.set_defaults(func=_status)

    ap = asub.add_parser(
        "app", help="manage the self-owned Saw GitHub App (Phase 1; official public App is #1277)",
    )
    apsub = ap.add_subparsers(dest="app_cmd", metavar="<app-command>")

    reg = apsub.add_parser(
        "register",
        help="register a self-owned Saw App via GitHub's manifest flow (stores credentials locally)",
    )
    reg.add_argument("--name", default="StayAwake Saw", help="App display name")
    reg.add_argument("--no-browser", action="store_true",
                     help="print the local URL instead of opening a browser")
    reg.set_defaults(func=_app_register)

    show = apsub.add_parser("show", help="show whether a local Saw App config is present")
    show.set_defaults(func=_app_show)

    p.set_defaults(func=_auth_root)


def _auth_root(a: argparse.Namespace) -> int:
    if not getattr(a, "auth_cmd", None):
        return _status(a)
    print("usage: saw auth status | saw auth app register | saw auth app show", flush=True)
    return 2


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
        "intents": rows,
    }
    if getattr(a, "json", False):
        print(json.dumps(payload, indent=2))
        return 0 if sess.live or sess.token is None else 1

    if not sess.token:
        print("• no GitHub credential (public scans still work)")
        print("  → `gh auth login`  or  `saw auth app register`")
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
    if github_app.is_configured():
        print(f"  Saw App config: {github_app.config_path()}")
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
        print("• no Saw GitHub App configured")
        print("  → `saw auth app register`")
        return 1
    if cfg:
        print(f"✓ local App config: {github_app.config_path()}")
        print(f"  app_id: {cfg.get('app_id')}")
        print(f"  slug:   {cfg.get('slug') or '(unknown — install from GitHub App settings)'}")
        if cfg.get("installation_id"):
            print(f"  installation_id: {cfg['installation_id']}")
        else:
            from stayawake.lib.github_app_manifest import install_url
            print(f"  → install on an account/org: {install_url(cfg.get('slug'))}")
            print("  → then set GH_APP_INSTALLATION_ID or re-run register after a single install")
    else:
        print("✓ App configured via environment (GH_APP_*)")
    return 0


def _app_register(a: argparse.Namespace) -> int:
    from stayawake.lib import github_app_manifest as manifest
    try:
        print("Starting GitHub App manifest registration…")
        print("  (needs PyJWT: pip install \"stayawake[app]\" — only required to mint tokens later)")
        payload = manifest.register_via_browser(
            name=getattr(a, "name", "StayAwake Saw") or "StayAwake Saw",
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
    print(f"  next: install the App on your user or org → {manifest.install_url(slug)}")
    print("  then: saw auth status   # confirm OPEN_GUARD_PR is allowed")
    print("  note: official public Saw App is deferred (#1277); this is your self-owned App.")
    return 0
