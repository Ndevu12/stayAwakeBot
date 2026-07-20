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
from stayawake.utils.render import SEVERITY, STATUS, paint, rule
from stayawake.utils import textsafe

# Colour is emitted only when the terminal sink says stdout is a TTY (and NO_COLOR isn't set) —
# the palette and `paint()` live in core.render so this surface and the audit report never drift
# on "what colour is critical?". Scan colours only the three worst severities it grades; padding
# is done on the PLAIN text first, so the escape codes never throw off column alignment.
_SEV_COLOR = {s: SEVERITY[s] for s in ("critical", "high", "medium")}


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
    return STATUS.get(label)     # INFECTED/SUSPECT/ERROR/clean → their code; anything else → None


def render_terminal(payload: dict[str, Any], *, color: bool = False,
                    collapse_clean_over: int = 0, detail: bool = True) -> str:
    s = payload["summary"]
    header = (f"{s['targets']} targets · {s['infected']} infected · "
              f"{s.get('suspicious', 0)} suspicious · "
              f"{s['findings']} findings ({s['critical']} critical, {s['high']} high)")
    if s.get("advisories"):
        header += f" · {s['advisories']} advisories"
    out = [f"Security scan — {payload['generated_at']}", "", header, ""]

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
        out.append("  ".join(rule(w) for w in widths))
        for label, total, sev, target in body:
            cells = [label.ljust(widths[0]), total.ljust(widths[1]),
                     sev.ljust(widths[2]), target]
            cells[0] = paint(cells[0], _label_color(label), on=color)  # pad first, then colour
            out.append("  ".join(cells))
    if clean_n:
        out.append(paint(f"… and {clean_n} clean repositor{'y' if clean_n == 1 else 'ies'} "
                         "— full inventory in the --json / -d report", STATUS["clean"], on=color))

    # Findings detail — only the INFECTED and SUSPECT repos (never clean/error), worst-first,
    # one block each. Within a block, severity tags are padded to a common width so the
    # signatures line up; evidence sits on its own, deeper-indented line. A blank line
    # separates the repo blocks.
    flagged = [r for r in ordered if (r["infected"] or r.get("suspicious")) and r["findings"]]
    if flagged and not detail:
        # Large fleet: the per-finding evidence would bury the terminal (hundreds of lines),
        # so the table above is the dashboard and the detail lives in the written report.
        n = len(flagged)
        out += ["", f"Per-finding detail for {n} flagged "
                    f"repositor{'y' if n == 1 else 'ies'} is in the full report (path below)."]
    elif flagged:
        out += ["", "Findings"]
        for r in flagged:
            label = _label(r)
            total = r["summary"]["total"]
            # Project header, then a rule under it so the project is clearly separated from
            # its findings. The rule length is computed from the PLAIN header (colour codes
            # have no display width), so it always matches the visible text.
            head_plain = f"{r['target']} — {label} · {total} finding(s)"
            out += ["",
                    f"  {paint(r['target'], _label_color(label), on=color)} — {label} "
                    f"· {total} finding(s)",
                    "  " + rule(len(head_plain))]
            tags = [f"[{f['severity']} · {f.get('confidence', 'confirmed')}]"
                    for f in r["findings"]]
            tw = max(len(t) for t in tags)
            for f, tag in zip(r["findings"], tags):
                loc = f["path"] + (f":{f['line']}" if f.get("line") else "")
                colored = paint(tag.ljust(tw), _SEV_COLOR.get(f["severity"]), on=color)
                # A visible bullet per finding; evidence sits under it, deeper-indented.
                out.append(f"    • {colored}  {f['signature_id']}  —  {loc}")
                if f.get("evidence"):
                    out.append(f"        evidence: {_fmt_evidence(f['evidence'])}")
                if f.get("fix_advice"):                          # actionable remediation (#1252)
                    out.append(f"        → fix: {textsafe.plain(f['fix_advice'])}")
                if f.get("reference"):
                    out.append(f"        → details: {textsafe.plain(f['reference'])}")
    # Dependency advisories — a SEPARATE, opt-in tier (ordinary CVEs). Listed for any target that
    # has them, including clean ones, and explicitly labelled as not affecting the verdict.
    advised = [r for r in ordered if r.get("advisories")]
    if advised:
        total_adv = sum(len(r["advisories"]) for r in advised)
        out += ["", f"Dependency advisories ({total_adv}) — informational; do not affect the verdict"]
        if not detail:
            out.append("Per-advisory detail is in the full report (path below).")
        else:
            for r in advised:
                out += ["", f"  {r['target']} — {len(r['advisories'])} advisor"
                            f"{'y' if len(r['advisories']) == 1 else 'ies'}"]
                for a in r["advisories"]:
                    loc = a["path"] + (f":{a['line']}" if a.get("line") else "")
                    out.append(f"    • [{a['severity']}]  {a['signature_id']}  —  {loc}")
                    if a.get("evidence"):
                        out.append(f"        {_fmt_evidence(a['evidence'])}")
                    if a.get("fix_advice"):                      # how to actually fix it (#1252)
                        out.append(f"        → fix: {textsafe.plain(a['fix_advice'])}")
                    if a.get("reference"):
                        out.append(f"        → details: {textsafe.plain(a['reference'])}")
    if s.get("suspicious"):
        out += ["", "suspicious = heuristic match(es) to review; not asserted as malware."]
    notes = _coverage_notes(payload)               # honest coverage caveats (#1222) — never gating
    if notes:
        out += ["", "Coverage notes (not gating):"] + [f"  • {n}" for n in notes]
    return "\n".join(out) + "\n"


def _coverage_notes(payload: dict[str, Any]) -> list[str]:
    """Unique, order-preserving coverage notes across all results (e.g. 'node_modules not deep-scanned',
    #1222) — the same note repeats per repo, so dedup to one line."""
    seen: dict[str, None] = {}
    for r in payload.get("results", []):
        for n in r.get("notes", []):
            seen.setdefault(n, None)
    return list(seen)


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
            if f.get("fix_advice"):                              # actionable remediation (#1252)
                # code-span the advice: it embeds an unvalidated package name, and a bare Markdown
                # string would let `x](http://evil)` render as an active link (textsafe.code contract).
                out.append(f"  - **fix:** {textsafe.code(f['fix_advice'])}")
            if f.get("reference"):
                out.append(f"  - details: {textsafe.sanitize(f['reference'])}")
        out.append("")
    if not any_f:
        out.append("_No findings — all scanned targets are clean._")

    # Dependency advisories — separate, opt-in, and explicitly non-gating.
    advised = [r for r in payload["results"] if r.get("advisories")]
    if advised:
        out += ["", "## Dependency advisories", "",
                "_Informational (ordinary CVEs on declared dependencies). These do **not** affect "
                "the verdict and never gate a scan._", ""]
        for r in advised:
            out.append(f"### {r['target']}")
            for a in r["advisories"]:
                loc = a["path"] + (f":{a['line']}" if a.get("line") else "")
                out.append(f"- **[{a['severity']}]** `{a['signature_id']}` — {loc}")
                out.append(f"  - {a['description']}")
                if a.get("evidence"):
                    out.append(f"  - evidence: {_fmt_evidence(a['evidence'])}")
                if a.get("fix_advice"):                          # how to actually fix it (#1252)
                    out.append(f"  - **fix:** {textsafe.code(a['fix_advice'])}")   # code-span: see above
                if a.get("reference"):
                    out.append(f"  - details: {textsafe.sanitize(a['reference'])}")
            out.append("")
    notes = _coverage_notes(payload)
    if notes:
        out += ["## Coverage notes", "", "_Not gating — what this scan did not look at._", ""]
        out += [f"- {n}" for n in notes] + [""]
    return "\n".join(out) + "\n"
