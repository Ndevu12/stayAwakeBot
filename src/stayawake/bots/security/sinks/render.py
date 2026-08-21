#!/usr/bin/env python3
"""Renderers for a scan payload.

Two surfaces, two shapes:
  * `render_terminal` — the interactive surface. An ALIGNED, column-padded table that
    lists only the targets that need attention (infected / suspicious / error) and
    summarises the clean ones as a count, so a 70-repo sweep isn't a wall of "clean".
  * `render_markdown` — the persisted `-d` bundle. Full markdown, every target listed
    (a complete inventory for the durable record).

Evidence shape differs by surface: a raw string on the terminal, a redact() fingerprint
dict when persisted — `_fmt_evidence` handles both.
"""
from __future__ import annotations

from typing import Any

from stayawake.bots.security.redaction import redact, render_redacted
from stayawake.utils.render import MARKER, SEVERITY, STATUS, paint, rule
from stayawake.utils import textsafe

_SEV_COLOR = {s: SEVERITY[s] for s in ("critical", "high", "medium")}


def _fmt_evidence(ev: Any, encode, *, composed: bool = False) -> str:
    """Evidence rendered for ONE surface — `encode` supplies that surface's escaping.

    A `redact()` fingerprint is already inert (a dict of hash, length and a `repr`-ed preview) and
    renders as-is. A raw snippet is attacker-chosen file bytes and must be encoded: it reached the
    terminal verbatim, so an escape sequence in a scanned file could retitle the window, clear the
    screen, or emit text a CI system reads as its own instructions."""
    if isinstance(ev, dict):                      # already a fingerprint (the persisted bundle)
        return encode(render_redacted(ev))        # repr() escapes control chars, not markdown
    if not composed:
        # A window of the scanned file. Shown as a fingerprint with a bounded preview rather than a
        # clean pasteable payload: handing one over invites hand-editing malware, which misses the
        # second stage and destroys the artifact. The preview is long enough to recognise a false
        # positive (see redaction.PREVIEW_LEN); `--json` still carries the whole snippet for tooling.
        return encode(render_redacted(redact(ev)))
    return encode(ev)


def _loc(item: dict, encode) -> str:
    """`path:line`, with the PATH encoded — whoever writes the repository names the file."""
    line = f":{item['line']}" if item.get("line") else ""
    # Truncate the PATH, never the line number: encoding the joined string put `:42` inside the
    # 300-char limit, so a 300+ char path (routine in nested node_modules) silently lost its line.
    encoded_line = encode(line, _LOC_LIMIT).strip("`") if line else ""
    room = _LOC_LIMIT - len(encoded_line) - 1
    path = encode(item["path"], _LOC_LIMIT).strip("`")
    if len(path) > room:
        path = "…" + path[-room:]
    return encode(f"{path}{line}", _LOC_LIMIT + len(path) + len(encoded_line))


def _verdict(r: dict[str, Any]) -> tuple[int, str] | None:
    """(sort-priority, label) for a non-clean result, or None for a clean one."""
    if r["infected"]:
        return 0, "INFECTED"
    if r.get("suspicious"):
        return 1, "SUSPECT"
    if r["error"]:
        return 2, "ERROR"
    return None


def _label(r: dict[str, Any]) -> str:
    v = _verdict(r)
    return v[1] if v else "clean"


def _label_color(label: str) -> str | None:
    return STATUS.get(label)     # INFECTED/SUSPECT/ERROR/clean → their code; anything else → None


def render_terminal(payload: dict[str, Any], *, color: bool = False,
                    collapse_clean_over: int = 0, detail: bool = True) -> str:
    s = payload["summary"]
    header = (f"{s['targets']} targets · {s['infected']} infected · "
              f"{s.get('suspicious', 0)} suspicious · "
              f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)")
    if s.get("advisories"):
        header += f" {MARKER['meta']} {s['advisories']} advisories"
    out = [f"Security scan — {payload['generated_at']}", "", header, ""]

    results = payload["results"]
    if not results:
        out.append("No targets scanned.")
        return "\n".join(out) + "\n"

    ordered = sorted(results, key=report_order)
    collapse = bool(collapse_clean_over) and len(results) > collapse_clean_over
    rows = [r for r in ordered if _verdict(r) is not None] if collapse else ordered
    clean_n = len(results) - len(rows)

    if rows:
        headers = ("STATUS", "FINDINGS", "SEVERITY", "TARGET")
        body = [(_label(r), str(r["summary"]["total"]),
                 r["summary"]["max_severity"] or "—", textsafe.plain(r["target"])) for r in rows]
        widths = [max(len(headers[i]), *(len(row[i]) for row in body)) for i in range(4)]
        out.append("  ".join(headers[i].ljust(widths[i]) for i in range(4)))
        out.append("  ".join(rule(w) for w in widths))
        for label, total, sev, target in body:
            cells = [label.ljust(widths[0]), total.ljust(widths[1]),
                     sev.ljust(widths[2]), target]
            cells[0] = paint(cells[0], _label_color(label), on=color)
            out.append("  ".join(cells))
    if clean_n:
        out.append(paint(f"… and {clean_n} clean repositor{'y' if clean_n == 1 else 'ies'} "
                         "— full inventory in the --json / -d report", STATUS["clean"], on=color))

    flagged = [r for r in ordered if (r["infected"] or r.get("suspicious")) and r["findings"]]
    if flagged and not detail:
        n = len(flagged)
        out += ["", f"Per-finding detail for {n} flagged "
                    f"repositor{'y' if n == 1 else 'ies'} is in the full report (path below)."]
    elif flagged:
        out += ["", "Findings"]
        for r in flagged:
            label = _label(r)
            total = r["summary"]["total"]
            safe_target = textsafe.plain(r["target"])   # repo-derived: never printed raw
            head_plain = f"{safe_target} — {label} {MARKER['meta']} {total} finding(s)"
            out += ["",
                    f"  {paint(safe_target, _label_color(label), on=color)} — {label} "
                    f"{MARKER['meta']} {total} finding(s)",
                    "  " + rule(len(head_plain))]
            tags = [f"[{f['severity']} {MARKER['meta']} {f.get('confidence', 'confirmed')}]"
                    for f in r["findings"]]
            tw = max(len(t) for t in tags)
            for f, tag in zip(r["findings"], tags):
                loc = _loc(f, textsafe.plain)
                colored = paint(tag.ljust(tw), _SEV_COLOR.get(f["severity"]), on=color)
                # A visible bullet per finding; evidence sits under it, deeper-indented.
                out.append(f"    {MARKER['info']} {colored}  {f['signature_id']}  —  {loc}")
                if f.get("evidence"):
                    ev = _fmt_evidence(f["evidence"], textsafe.quoted,
                                       composed=f.get("composed_evidence", False))
                    out.append(f"        evidence: {ev}")
                if f.get("fix_advice"):                          # actionable remediation
                    out.append(f"        {MARKER['detail']} fix: {textsafe.plain(f['fix_advice'])}")
                if f.get("reference"):
                    out.append(f"        {MARKER['detail']} details: {textsafe.plain(f['reference'])}")
    advised = [r for r in ordered if r.get("advisories")]
    if advised:
        total_adv = sum(len(r["advisories"]) for r in advised)
        out += ["", f"Dependency advisories ({total_adv}) — informational; do not affect the verdict"]
        if not detail:
            out.append("Per-advisory detail is in the full report (path below).")
        else:
            for r in advised:
                out += ["", f"  {textsafe.plain(r['target'])} — {len(r['advisories'])} advisor"
                            f"{'y' if len(r['advisories']) == 1 else 'ies'}"]
                for a in r["advisories"]:
                    loc = _loc(a, textsafe.plain)
                    out.append(f"    {MARKER['info']} [{a['severity']}]  {a['signature_id']}  —  {loc}")
                    if a.get("evidence"):
                        adv_ev = _fmt_evidence(a["evidence"], textsafe.quoted,
                                               composed=a.get("composed_evidence", False))
                        out.append(f"        {adv_ev}")
                    if a.get("fix_advice"):                      # how to actually fix it
                        out.append(f"        {MARKER['detail']} fix: {textsafe.plain(a['fix_advice'])}")
                    if a.get("reference"):
                        out.append(f"        {MARKER['detail']} details: {textsafe.plain(a['reference'])}")
    if s.get("suspicious"):
        out += ["", "suspicious = heuristic match(es) to review; not asserted as malware."]
    notes = _coverage_notes(payload)
    if notes:
        out += ["", "Coverage notes (not gating):"] + [f"  {MARKER['info']} {n}" for n in notes]
    # nothing is infected — the exact moment a user might read "clean" and rotate a token, which can
    # arm a rotation-wiper daemon. Terminal-only, never gates; the authoritative host verdict is
    # `saw audit` (which now withholds its all-clear until the persistence surface is verified).
    if not s.get("infected"):
        out += ["", "Host note: a clean repo scan is NOT a host all-clear — it does not check host "
                    "persistence. Before rotating any credential, run `saw audit` (rotating while a "
                    "persistence daemon is live can arm a home-directory wiper)."]
    return "\n".join(out) + "\n"


def _coverage_notes(payload: dict[str, Any]) -> list[str]:
    """Unique, order-preserving coverage notes across all results (e.g. 'node_modules not deep-scanned',) — the same note repeats per repo, so dedup to one line."""
    seen: dict[str, None] = {}
    for r in payload.get("results", []):
        for n in r.get("notes", []):
            seen.setdefault(n, None)
    return list(seen)


_LOC_LIMIT = 300          # textsafe's own default; named here because `_loc` budgets against it

_URL_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                "-._~:/?#@!$&'*+,;=%")


def _md_url(value: str) -> str:
    """A clean http(s) URL bare so it stays clickable; anything else code-spanned.

    Bare was unsafe (a crafted `reference` injected markdown into the persisted report) and
    code-spanning everything cost the reader the link. Validating gives both."""
    text = str(value)
    if (text.startswith(("https://", "http://")) and len(text) <= 300
            and all(ch in _URL_SAFE for ch in text)):
        return text
    return textsafe.code(text)


def report_order(result: dict[str, Any]) -> tuple:
    """Worst-first: infected → suspect → error → clean, then most findings, then name.

    Module-level because BOTH renderers answer the same question, and the persisted bundle used to
    answer it differently — it listed targets in scan order, so an infected repository could sit
    below a clean one in the file kept as the record."""
    verdict = _verdict(result)
    return (verdict[0] if verdict else 3, -result["summary"]["total"], result["target"])


def render_markdown(payload: dict[str, Any]) -> str:
    s = payload["summary"]
    out = [f"# Security scan — {payload['generated_at']}", "",
           f"**{s['targets']} targets** · {s['infected']} infected · "
           f"{s.get('suspicious', 0)} suspicious · "
           f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)", "",
           "_Verdict: **infected** = a confirmed (high-confidence) signature matched; "
           "**suspicious** = only heuristic match(es) that benign code can also produce — "
           "review, not asserted as malware._", "",
           "| Target | Source | Status | Findings | Top severity |",
           "|--------|--------|--------|----------|--------------|"]
    for r in sorted(payload["results"], key=report_order):
        status = ("❌ INFECTED" if r["infected"]
                  else "🟡 SUSPICIOUS" if r.get("suspicious")
                  else "⚠️ error" if r["error"] else "✅ clean")
        out.append(f"| {textsafe.table_cell(r['target'])} | {textsafe.table_cell(r['source'])} | "
                   f"{status} | "
                   f"{r['summary']['total']} | {r['summary']['max_severity'] or '—'} |")
    out += ["", "## Findings", ""]
    any_f = False
    for r in sorted(payload["results"], key=report_order):
        if not r["findings"]:
            continue
        any_f = True
        out.append(f"### {textsafe.code(r['target'])}")
        for f in r["findings"]:
            loc = _loc(f, textsafe.code)
            out.append(f"- **[{f['severity']} {MARKER['meta']} {f.get('confidence', 'confirmed')}]** "
                       f"`{f['signature_id']}` — {loc}")
            out.append(f"  - {f['description']}")
            if f.get("evidence"):
                ev = _fmt_evidence(f["evidence"], textsafe.code,
                                   composed=f.get("composed_evidence", False))
                out.append(f"  - evidence: {ev}")
            if f.get("fix_advice"):                              # actionable remediation
                # code-span the advice: it embeds an unvalidated package name, and a bare Markdown
                # string would let `x](http://evil)` render as an active link (textsafe.code contract).
                out.append(f"  - **fix:** {textsafe.code(f['fix_advice'])}")
            if f.get("reference"):
                out.append(f"  - details: {_md_url(f['reference'])}")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")

    advised = [r for r in sorted(payload["results"], key=report_order) if r.get("advisories")]
    if advised:
        out += ["", "## Dependency advisories", "",
                "_Informational (ordinary CVEs on declared dependencies). These do **not** affect "
                "the verdict and never gate a scan._", ""]
        for r in advised:
            out.append(f"### {textsafe.code(r['target'])}")
            for a in r["advisories"]:
                loc = _loc(a, textsafe.code)
                out.append(f"- **[{a['severity']}]** `{a['signature_id']}` — {loc}")
                out.append(f"  - {a['description']}")
                if a.get("evidence"):
                    adv_ev = _fmt_evidence(a["evidence"], textsafe.code,
                                           composed=a.get("composed_evidence", False))
                    out.append(f"  - evidence: {adv_ev}")
                if a.get("fix_advice"):                          # how to actually fix it
                    out.append(f"  - **fix:** {textsafe.code(a['fix_advice'])}")   # code-span: see above
                if a.get("reference"):
                    out.append(f"  - details: {_md_url(a['reference'])}")
            out.append("")
    notes = _coverage_notes(payload)
    if notes:
        out += ["## Coverage notes", "", "_Not gating — what this scan did not look at._", ""]
        out += [f"- {textsafe.code(n)}" for n in notes] + [""]
    return "\n".join(out) + "\n"
