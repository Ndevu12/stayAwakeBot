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

from stayawake.bots.security.redaction import render_redacted

# ANSI colours — applied only when the terminal sink says stdout is a TTY (and NO_COLOR
# isn't set). Status tokens and severity tags get the colour; padding is done on the
# plain text first, so the escape codes never throw off column alignment.
_RESET = "\033[0m"
_GREEN = "\033[32m"
_STATUS_COLOR = {"INFECTED": "\033[1;31m", "SUSPECT": "\033[33m", "ERROR": "\033[35m"}
_SEV_COLOR = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m"}


def _c(text: str, code: str | None, on: bool) -> str:
    return f"{code}{text}{_RESET}" if on and code else text


def _fmt_evidence(ev: Any) -> str:
    if isinstance(ev, dict):                 # a redact() fingerprint (persisted artifacts)
        return render_redacted(ev)
    return f"`{ev}`"                         # a raw snippet (ephemeral terminal)


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
    return _STATUS_COLOR.get(label) or (_GREEN if label == "clean" else None)


def render_terminal(payload: dict[str, Any], *, color: bool = False,
                    collapse_clean_over: int = 0) -> str:
    s = payload["summary"]
    out = [f"Security scan — {payload['generated_at']}", "",
           f"{s['targets']} targets · {s['infected']} infected · "
           f"{s.get('suspicious', 0)} suspicious · "
           f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)", ""]

    results = payload["results"]
    if not results:
        out.append("No targets scanned.")
        return "\n".join(out) + "\n"

    # Table, worst-first (infected → suspect → error → clean), then by finding count, then
    # name — problems sit at the top. For a LARGE fleet the clean rows are collapsed to a
    # count (clean = nothing to look at); the full inventory still lives in --json / -d.
    def sort_key(r):
        v = _verdict(r)
        return (v[0] if v else 3, -r["summary"]["total"], r["target"])

    ordered = sorted(results, key=sort_key)
    collapse = bool(collapse_clean_over) and len(results) > collapse_clean_over
    rows = [r for r in ordered if _verdict(r) is not None] if collapse else ordered
    clean_n = len(results) - len(rows)

    if rows:
        headers = ("STATUS", "FINDINGS", "SEVERITY", "TARGET")
        body = [(_label(r), str(r["summary"]["total"]),
                 r["summary"]["max_severity"] or "—", r["target"]) for r in rows]
        widths = [max(len(headers[i]), *(len(row[i]) for row in body)) for i in range(4)]
        out.append("  ".join(headers[i].ljust(widths[i]) for i in range(4)))
        out.append("  ".join("─" * w for w in widths))
        for label, total, sev, target in body:
            cells = [label.ljust(widths[0]), total.ljust(widths[1]),
                     sev.ljust(widths[2]), target]
            cells[0] = _c(cells[0], _label_color(label), color)  # pad first, then colour
            out.append("  ".join(cells))
    if clean_n:
        out.append(_c(f"… and {clean_n} clean repositor{'y' if clean_n == 1 else 'ies'} "
                      "— full inventory in the --json / -d report", _GREEN, color))

    # Findings detail — only the INFECTED and SUSPECT repos (never clean/error), worst-first,
    # one block each. Within a block, severity tags are padded to a common width so the
    # signatures line up; evidence sits on its own, deeper-indented line. A blank line
    # separates the repo blocks.
    detail = [r for r in ordered if (r["infected"] or r.get("suspicious")) and r["findings"]]
    if detail:
        out += ["", "Findings"]
        for r in detail:
            label = _label(r)
            total = r["summary"]["total"]
            # Project header, then a rule under it so the project is clearly separated from
            # its findings. The rule length is computed from the PLAIN header (colour codes
            # have no display width), so it always matches the visible text.
            head_plain = f"{r['target']} — {label} · {total} finding(s)"
            out += ["",
                    f"  {_c(r['target'], _label_color(label), color)} — {label} "
                    f"· {total} finding(s)",
                    "  " + "─" * len(head_plain)]
            tags = [f"[{f['severity']} · {f.get('confidence', 'confirmed')}]"
                    for f in r["findings"]]
            tw = max(len(t) for t in tags)
            for f, tag in zip(r["findings"], tags):
                loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
                colored = _c(tag.ljust(tw), _SEV_COLOR.get(f["severity"]), color)
                # A visible bullet per finding; evidence sits under it, deeper-indented.
                out.append(f"    • {colored}  {f['signature_id']}  —  {loc}")
                if f.get("evidence"):
                    out.append(f"        evidence: {_fmt_evidence(f['evidence'])}")
    if s.get("suspicious"):
        out += ["", "suspicious = heuristic match(es) to review; not asserted as malware."]
    return "\n".join(out) + "\n"


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
    for r in payload["results"]:
        status = ("❌ INFECTED" if r["infected"]
                  else "🟡 SUSPICIOUS" if r.get("suspicious")
                  else "⚠️ error" if r["error"] else "✅ clean")
        out.append(f"| {r['target']} | {r['source']} | {status} | "
                   f"{r['summary']['total']} | {r['summary']['max_severity'] or '—'} |")
    out += ["", "## Findings", ""]
    any_f = False
    for r in payload["results"]:
        if not r["findings"]:
            continue
        any_f = True
        out.append(f"### {r['target']}")
        for f in r["findings"]:
            loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
            out.append(f"- **[{f['severity']} · {f.get('confidence', 'confirmed')}]** "
                       f"`{f['signature_id']}` — {loc}")
            out.append(f"  - {f['description']}")
            if f.get("evidence"):
                out.append(f"  - evidence: {_fmt_evidence(f['evidence'])}")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")
    return "\n".join(out) + "\n"
