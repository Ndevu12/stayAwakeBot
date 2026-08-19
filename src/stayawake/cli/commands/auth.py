#!/usr/bin/env python3
"""`saw auth` — credential status + operator-managed StayAwakeBot GitHub App registration."""
from __future__ import annotations

import argparse
import json
import sys

from stayawake.cli.helptext import add_command
from stayawake.core.identity import Intent, require, resolve_session
from stayawake.lib import github_app
from stayawake.utils import env
from stayawake.utils.render import LINK, SEVERITY, block, paint, term_width
from stayawake.utils.streaming import Streamer, status, stream_enabled
from stayawake.utils.terminal import supports_color


def register(sub) -> None:
    p = add_command(
        sub, "auth", aliases=["a"],
        help="show GitHub credential/capability status; register a StayAwakeBot GitHub App",
        description=(
            "Show your GitHub credential and capability status, and register an "
            "operator-managed StayAwakeBot GitHub App. Most of saw works offline; auth only "
            "concerns the paths that need a credential — remote scanning, `saw fix --pr` and "
            "`saw guard setup --pr`. Bare `saw auth` is `saw auth status`."),
        examples=[
            ("saw auth", "credential + capability status"),
            ("saw auth status --json", "machine-readable; non-zero if guard PRs are denied"),
            ("saw auth app register", "register + install the App (browser flow)"),
            ("saw auth app show", "which App is configured, and how to install it"),
        ])
    asub = p.add_subparsers(dest="auth_cmd", metavar="<auth-command>")

    st = add_command(
        asub, "status",
        help="show active credential + capability gate for key intents",
        description=(
            "Report the active credential — source, actor, whether it is live — its scopes or "
            "capabilities, whether a StayAwakeBot App is configured, and an intent gate: for "
            "each key action (read a remote, open a fix PR, open a guard PR) whether this "
            "credential is allowed, what is missing, and the command that fixes it. Exits "
            "non-zero when a live credential cannot open a guard PR, so it drops into CI."),
        examples=[
            ("saw auth status", "credential, capabilities and the intent gate"),
            ("saw auth status --json", "machine-readable, for a CI gate"),
        ])
    st.add_argument("--json", action="store_true", help="machine-readable output")
    st.add_argument("--no-stream", action="store_true", help="disable animated output")
    st.set_defaults(func=_status)

    ap = add_command(
        asub, "app",
        help="manage the operator-managed StayAwakeBot GitHub App",
        description=(
            "Manage the operator-managed StayAwakeBot GitHub App — the recommended credential "
            "for acting across many repos and accounts, since its per-account installation "
            "tokens are scoped and revocable. Token signing is built in, so there is no crypto "
            "extra to install. You own the registration and the credentials."),
        examples=[
            ("saw auth app register", "register + install it (browser flow)"),
            ("saw auth app show", "is one configured, and where?"),
        ])
    apsub = ap.add_subparsers(dest="app_cmd", metavar="<app-command>")

    reg = add_command(
        apsub, "register",
        help="register + install a StayAwakeBot App via GitHub's manifest flow "
             "(stores credentials locally)",
        description=(
            "Register and install a new App through GitHub's browser manifest flow, storing the "
            "credentials locally at mode 0600. Idempotent: with an App already configured it "
            "mints no duplicate (App names are globally unique) and instead points you at "
            "installing that same App on more accounts and orgs."),
        examples=[
            ("saw auth app register", "browser flow; credentials stay local"),
            ("saw auth app register --no-browser", "print the URL instead of opening it"),
            ("saw auth app register --replace", "force a brand-new App"),
        ])
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

    show = add_command(
        apsub, "show",
        help="show whether a local StayAwakeBot App config is present",
        description=(
            "Show the local App config — id, name, slug, installation — with the URLs for "
            "installing it on another account or org and for its settings page."),
        examples=[
            ("saw auth app show", "which App is configured, and where"),
            ("saw auth app register", "none configured? register one"),
        ])
    show.add_argument("--no-stream", action="store_true", help="disable animated output")
    show.set_defaults(func=_app_show)

    p.set_defaults(func=_auth_root)


def _ui(a: argparse.Namespace) -> tuple[Streamer, bool, int]:
    """(streamer, colour-on, width) for rendered `saw auth` output — same rendering toolkit as
    `saw audit` (utils.render): a stdout Streamer honoring `--no-stream`, colour gated by the stdout
    TTY (NO_COLOR / CI / pipe → plain), and the live terminal width for wrapping."""
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=getattr(a, "no_stream", False)))
    return prog, supports_color(sys.stdout), term_width()


def _cmd(text: str, color: bool, *, indent: int = 6) -> str:
    """A copy-pasteable command / URL on its OWN line, rendered distinctly (bold cyan, like a link)
    and NEVER reflowed — so every suggestion is clearly visible and safely selectable, exactly like
    `saw audit` renders its commands. Rationale stays in the surrounding prose; the command stands
    alone on its line."""
    return " " * indent + paint(text, LINK, on=color)


def _auth_root(a: argparse.Namespace) -> int:
    if not getattr(a, "auth_cmd", None):
        return _status(a)
    print("usage: saw auth status | saw auth app register | saw auth app show", flush=True)
    return 2


def _app_readiness_block(color: bool, width: int) -> list[str]:
    """Rendered App config vs mint-readiness section (blank-line separated, wrapped, coloured).
    Signing is BUILT IN (no crypto extra), so once the App is configured the only remaining step is
    completing the installation."""
    if not github_app.is_configured():
        return []
    cfg = github_app.load_config() or {}
    out: list[str] = ["", paint("StayAwakeBot App", SEVERITY["info"], on=color)]
    label = cfg.get("name") or cfg.get("slug")
    if label:
        suffix = f" ({cfg['slug']})" if cfg.get("slug") and cfg.get("name") else ""
        out += block(f"{label}{suffix}", indent=2, width=width)
    out += block(str(github_app.config_path()), indent=2, width=width,
                 marker="config: ", code=SEVERITY["info"], color=color)
    if not (cfg.get("installation_id") or env.get(github_app.INSTALLATION_ID_ENV)):
        from stayawake.lib.github_app_manifest import install_url
        out += block("registered but not installed yet", indent=2, width=width,
                     marker="⚠ ", code=SEVERITY["warning"], color=color)
        out.append("    " + paint(install_url(cfg.get("slug")), LINK, on=color))
    else:
        out += block("ready to mint installation tokens", indent=2, width=width,
                     marker="✓ ", code=SEVERITY["ok"], color=color)
    return out


def _status(a: argparse.Namespace) -> int:
    prog, color, width = _ui(a)
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
        lines = [paint("• no GitHub credential", SEVERITY["info"], on=color)
                 + " — public scans still work"]
        lines += block("authenticate to clone private repos and open PRs:", indent=2, width=width)
        lines.append(_cmd("gh auth login", color))
        lines.append(_cmd("saw auth app register", color))
        lines += _app_readiness_block(color, width)
        prog.line("\n".join(lines).rstrip())
        return 0

    who = sess.actor or sess.source or "?"
    mark = paint("✓", SEVERITY["ok"], on=color) if sess.live else paint("✗", SEVERITY["warning"], on=color)
    lines = [f"{mark} credential: {sess.source} as {who}"
             + ("" if sess.live else f" — {sess.detail or 'not live'}")]
    if sess.scopes is not None:
        lines += block(f"classic scopes: {', '.join(sorted(sess.scopes)) or '(none)'}",
                       indent=2, width=width)
    elif sess.capabilities is not None:
        lines += block(f"capabilities: {', '.join(sorted(c.value for c in sess.capabilities))}",
                       indent=2, width=width)
    else:
        lines += block("capabilities: unknown (fine-grained PAT?) — delivery will classify push "
                       "failures", indent=2, width=width)
    lines += _app_readiness_block(color, width)

    lines += ["", paint("intent gate", SEVERITY["info"], on=color)]
    for row in rows:
        ok = row["allowed"]
        rmark = paint("✓", SEVERITY["ok"], on=color) if ok else paint("✗", SEVERITY["warning"], on=color)
        lines.append(f"  {rmark} {row['intent']}")
        if not ok:
            if row["missing"]:
                lines += block("missing: " + ", ".join(row["missing"]), indent=6, width=width)
            for u in row["upgrades"]:
                if u["detail"]:
                    lines += block(u["detail"], indent=6, width=width, marker="→ ",
                                   code=SEVERITY["info"], color=color)
                if u["command"]:
                    lines.append(_cmd(u["command"], color, indent=8))
    prog.line("\n".join(lines).rstrip())
    guard = next(r for r in rows if r["intent"] == Intent.OPEN_GUARD_PR.value)
    return 0 if guard["allowed"] or not sess.live else 1


def _app_show(a: argparse.Namespace) -> int:
    prog, color, width = _ui(a)
    cfg = github_app.load_config()
    if not cfg and not github_app.is_configured():
        lines = [paint("• no StayAwakeBot GitHub App configured", SEVERITY["info"], on=color)]
        lines += block("saw auth app register", indent=2, width=width, marker="→ ",
                       code=SEVERITY["info"], color=color)
        prog.line("\n".join(lines).rstrip())
        return 1
    if not cfg:
        prog.line(paint("✓ App configured via environment (GH_APP_*)", SEVERITY["ok"], on=color))
        return 0

    from stayawake.lib.github_app_manifest import install_url, settings_url
    slug = cfg.get("slug")
    lines = [paint(f"✓ local App config: {github_app.config_path()}", SEVERITY["ok"], on=color)]
    lines += block(f"app_id: {cfg.get('app_id')}", indent=2, width=width)
    lines += block(f"name:   {cfg.get('name') or '(unknown)'}", indent=2, width=width)
    lines += block(f"slug:   {slug or '(unknown — install from GitHub App settings)'}",
                   indent=2, width=width)
    if cfg.get("installation_id"):
        lines += block(f"installation_id: {cfg['installation_id']}", indent=2, width=width)

    lines += ["", paint("Install on more accounts/orgs", SEVERITY["info"], on=color)
              + "  · a GitHub App is per-account"]
    lines.append(_cmd(install_url(slug), color, indent=2))
    lines += block("no account picker there? the App is 'Only on this account' — set it to 'Any "
                   "account' in App settings first:", indent=2, width=width)
    lines.append(_cmd(settings_url(slug, app_id=cfg.get("app_id")), color, indent=2))
    prog.line("\n".join(lines).rstrip())
    return 0


def _already_registered(prog: Streamer, color: bool, width: int, a: argparse.Namespace) -> int | None:
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
        prog.line("\n".join(block(
            "the previously registered StayAwakeBot App no longer exists on GitHub — registering a "
            "new one.", width=width, marker="⚠ ", code=SEVERITY["warning"], color=color)))
        return None

    label = cfg.get("name") or slug or f"app_id={cfg.get('app_id')}"
    suffix = f" ({slug})" if slug and cfg.get("name") else ""
    settings = settings_url(slug, app_id=cfg.get("app_id"))
    lines = [paint(f"✓ a StayAwakeBot App is already registered on GitHub: {label}{suffix}",
                   SEVERITY["ok"], on=color)]
    if exists is None:
        lines += block("couldn't confirm it still exists on GitHub (offline, rate-limited, or a "
                       "key/clock issue) — so not creating a duplicate; use --replace to force a "
                       "new App.", indent=2, width=width)
    lines += block(str(github_app.config_path()), indent=2, width=width,
                   marker="config: ", code=SEVERITY["info"], color=color)
    lines.append("")
    lines += block("This is the App REGISTRATION — it stays even after you uninstall the App "
                   "(uninstalling only removes an installation, not the registration).", width=width)
    lines += ["", paint("What you probably want", SEVERITY["info"], on=color)]
    lines += block("run it on another account/org — install this SAME App there (a GitHub App is "
                   "per-account, so each org needs its own installation):", indent=2, width=width,
                   marker="• ")
    lines.append(_cmd(install_url(slug), color))
    lines += block("no account picker there? the App is 'Only on this account' — set it to 'Any "
                   "account' first:", indent=4, width=width)
    lines.append(_cmd(settings, color))
    lines += block("start over — delete the registration (Advanced → Delete GitHub App), then "
                   "register again:", indent=2, width=width, marker="• ")
    lines.append(_cmd(settings, color))
    lines += block("replace it now with a brand-new App:", indent=2, width=width, marker="• ")
    lines.append(_cmd("saw auth app register --replace", color))
    prog.line("\n".join(lines).rstrip())
    return 0


def _app_register(a: argparse.Namespace) -> int:
    from stayawake.lib import github_app_manifest as manifest
    prog, color, width = _ui(a)
    early = _already_registered(prog, color, width, a)
    if early is not None:
        return early
    try:
        prog.line(paint("Registering a StayAwakeBot GitHub App", SEVERITY["info"], on=color))
        prog.line("\n".join(block("a browser will open: create App → install on your account/org → "
                                  "return here", indent=2, width=width)))
        with status("waiting for GitHub (complete the flow in your browser)…", enabled=prog.enabled):
            payload = manifest.register_via_browser(
                name=getattr(a, "name", "StayAwakeBot") or "StayAwakeBot",
                open_browser=not getattr(a, "no_browser", False),
            )
    except github_app.GithubAppError as e:
        prog.line(paint(f"✗ {e}", SEVERITY["warning"], on=color))
        return 2
    except Exception as e:  # noqa: BLE001
        prog.line(paint(f"✗ registration failed: {e}", SEVERITY["warning"], on=color))
        return 2

    slug = payload.get("slug")
    lines = [paint(f"✓ registered App id={payload.get('id')} slug={slug}", SEVERITY["ok"], on=color)]
    lines += block(f"credentials saved to {github_app.config_path()} (mode 0600)",
                   indent=2, width=width)
    if payload.get("_installed") and payload.get("installation_id"):
        lines += block(f"installed (installation_id={payload['installation_id']})", indent=2,
                       width=width, marker="✓ ", code=SEVERITY["ok"], color=color)
    else:
        lines += block("App registered but install was not completed in this session — finish it:",
                       indent=2, width=width, marker="⚠ ", code=SEVERITY["warning"], color=color)
        lines.append(_cmd(payload.get("_install_url") or manifest.install_url(slug), color))
    icon = payload.get("_icon_path")
    settings = payload.get("_settings_url")
    if icon and settings:
        lines += ["", paint("branding", SEVERITY["info"], on=color)]
        lines += block("upload the StayAwakeBot icon in App settings → Display information:",
                       indent=2, width=width)
        lines.append(_cmd(settings, color))
        lines += block(f"icon: {icon}", indent=2, width=width)
    lines += ["", paint("next", SEVERITY["info"], on=color) + "  · confirm open_guard_pr is allowed"]
    lines.append(_cmd("saw auth status", color, indent=2))
    lines += block("this App is operator-managed — you own the registration and credentials.",
                   indent=2, width=width)
    prog.line("\n".join(lines).rstrip())
    return 0 if payload.get("_installed") else 1
