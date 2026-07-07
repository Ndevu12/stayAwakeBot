#!/usr/bin/env python3
"""Offline advisory database — cache + `saw db update` fetch (#1120).

The ONE network egress in the whole scanner. `saw db update` bulk-downloads the OSV per-ecosystem
export (`<base>/<bucket>/all.zip`) into a local cache; every scan then reads only that cache, so
detection stays offline and deterministic. The download URL names only the **ecosystem** — never
a package — so an update can't leak the dependency graph (we pull advisories, not your manifest,
and never query per-package online).

Phase 1b keeps only **malicious** records with an **explicit affected-version list** (see
`osv.is_malicious` / `parse_osv_record`); ordinary CVEs and range-only advisories are deferred to
the vulnerability tier (#1121) and the range comparators (#1124). The inline `known_bad` seed in
signatures.yml always ships, so the DB is a *superset*, never a prerequisite — no cache → scans
fall back to the seed, exactly as before.

Cache location and snapshot pinning/verification are finalized in the trust-hardening phase
(#1126); today the cache is a plain user-cache directory with a basic per-ecosystem manifest.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import ssl
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterator

from stayawake.bots.security.dependencies.corpus import AdvisoryCorpus
from stayawake.bots.security.dependencies.ecosystems import PURL_TO_OSV
from stayawake.bots.security.dependencies.osv import (
    OsvAffected, OsvRange, OsvRecord, parse_osv_record)
from stayawake.core.timeutil import now_iso

_SCHEMA = 2   # bumped for the #1126 manifest (snapshot + generated_at); older caches lack these
_OSV_EXPORT_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# PURL type → OSV export bucket. The single source of truth lives in `ecosystems.py` (the corpus
# canonicalizes the other direction from the same table, so they can't drift).
_OSV_BUCKETS = PURL_TO_OSV

# Verify TLS against certifi's portable CA bundle (the OS store isn't always wired to OpenSSL on
# python.org builds) — the same rationale as core/adapters/github_api.py.
try:
    import certifi
    _SSL_CTX: ssl.SSLContext = ssl.create_default_context(cafile=certifi.where())
except Exception:  # noqa: BLE001 — a TLS-setup hiccup must never crash import
    _SSL_CTX = ssl.create_default_context()

# load_corpus is called once per scanned target; memoize by (cache dir, manifest mtime) so a
# fleet sweep parses the cache once, and a fresh `db update` (which rewrites the manifest, bumping
# mtime, and clears this) is picked up.
_CORPUS_MEMO: dict[tuple[str, float], AdvisoryCorpus | None] = {}


# ── cache location ────────────────────────────────────────────────────────────────────
def default_cache_dir() -> Path:
    """`$SAW_ADVISORY_CACHE_DIR`, else `$XDG_CACHE_HOME/saw/advisories`, else
    `~/.cache/saw/advisories`. (The global-vs-repo-pinned decision is #1126.)"""
    env = os.environ.get("SAW_ADVISORY_CACHE_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "saw" / "advisories"


def _records_path(cache_dir: Path, eco: str) -> Path:
    # JSON Lines (one record per line) so the corpus streams record-by-record at scan time — a
    # fully-populated ecosystem is hundreds of thousands of records, far too many to hold as one
    # parsed list. Determinism: records are sorted before writing, so the bytes are reproducible.
    return cache_dir / "records" / f"{eco}.jsonl"


def _manifest_path(cache_dir: Path) -> Path:
    return cache_dir / "manifest.json"


# ── fetch (the only network egress) ─────────────────────────────────────────────────────
def fetch_ecosystem_zip(bucket: str, *, timeout: int = 120) -> bytes:
    """Download an OSV per-ecosystem export. Names only the ecosystem — graph-blind."""
    url = f"{_OSV_EXPORT_BASE}/{bucket}/all.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "StayAwakeBot/1.0 (saw db update)"})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
        return resp.read()


def _iter_zip_records(zip_bytes: bytes) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                obj = json.loads(zf.read(name))
            except (json.JSONDecodeError, OSError, KeyError):
                continue
            if isinstance(obj, dict):
                yield obj


# ── update ──────────────────────────────────────────────────────────────────────────────
def supported_ecosystems() -> list[str]:
    return list(_OSV_BUCKETS.keys())


def resolved_ecosystems(names: list[str] | None = None) -> list[str]:
    """The ecosystems to update: the requested subset, or all supported ones."""
    return list(names) if names else supported_ecosystems()


def update_ecosystem(eco: str, cache_dir: str | Path | None = None, *,
                     fetch: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    """Fetch one ecosystem's export, keep the malicious+explicit-version records, write its cache
    file, and return its manifest entry. `fetch` is injectable so tests never touch the network;
    when None it resolves to the module-level `fetch_ecosystem_zip` (so a monkeypatch of that
    attribute is also honored)."""
    fetch = fetch or fetch_ecosystem_zip
    cache_dir = Path(cache_dir or default_cache_dir())
    bucket = _OSV_BUCKETS.get(eco)
    if bucket is None:
        raise ValueError(f"unsupported ecosystem: {eco!r} (supported: {supported_ecosystems()})")
    (cache_dir / "records").mkdir(parents=True, exist_ok=True)

    # Keep every record with an explicit affected-version list — BOTH malware (drives the verdict)
    # and ordinary CVEs (the opt-in advisory tier), including range-based ones (#1124). Each is
    # tagged with its `malicious` flag so the corpus can serve the two tiers separately.
    records: list[dict[str, Any]] = []
    for raw in _iter_zip_records(fetch(bucket)):
        rec = parse_osv_record(raw)
        if rec is not None:
            records.append(_record_to_json(rec))
    # Deterministic on-disk bytes (reproducible CI, #1126): sort, then write one record per line and
    # hash incrementally — never materialize the whole file as a single string.
    records.sort(key=lambda r: (r["id"], r["affected"][0]["name"] if r["affected"] else ""))
    hasher = hashlib.sha256()
    with _records_path(cache_dir, eco).open("w", encoding="utf-8") as fh:
        for r in records:
            line = json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
            fh.write(line)
            hasher.update(line.encode("utf-8"))
    malicious = sum(1 for r in records if r["malicious"])
    return {"ecosystem": eco, "count": len(records), "malicious": malicious,
            "vulnerabilities": len(records) - malicious,
            "sha256": hasher.hexdigest(),
            "source": f"{_OSV_EXPORT_BASE}/{bucket}/all.zip"}


def write_manifest(cache_dir: str | Path | None, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Write the manifest that stitches the per-ecosystem cache files together, and invalidate the
    in-process corpus memo so the next scan sees the fresh data."""
    cache_dir = Path(cache_dir or default_cache_dir())
    cache_dir.mkdir(parents=True, exist_ok=True)
    ecosystems = {r["ecosystem"]: {k: r[k] for k in
                                   ("count", "malicious", "vulnerabilities", "sha256", "source")}
                  for r in results}
    manifest = {"schema": _SCHEMA,
                # `snapshot` is a deterministic fingerprint of the whole DB (from the per-ecosystem
                # content hashes) — pin it in CI for reproducible gates. `generated_at` is
                # informational (staleness) and deliberately OUTSIDE the snapshot, so it doesn't
                # perturb the fingerprint.
                "snapshot": snapshot_digest(ecosystems),
                "generated_at": now_iso(),
                "ecosystems": ecosystems}
    _manifest_path(cache_dir).write_text(json.dumps(manifest, sort_keys=True, indent=2),
                                         encoding="utf-8")
    _CORPUS_MEMO.clear()
    return manifest


def snapshot_digest(ecosystems: dict[str, Any]) -> str:
    """A short, deterministic fingerprint of a DB from its per-ecosystem content hashes — same data
    → same snapshot, so CI can pin it."""
    h = hashlib.sha256()
    for eco in sorted(ecosystems):
        h.update(f"{eco}:{ecosystems[eco].get('sha256', '')}\n".encode("utf-8"))
    return h.hexdigest()[:16]


def _file_sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def update(ecosystems: list[str] | None = None, cache_dir: str | Path | None = None, *,
           fetch: Callable[[str], bytes] | None = None,
           log: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Update every requested ecosystem and write the manifest (programmatic entry point)."""
    results = []
    for eco in resolved_ecosystems(ecosystems):
        if log:
            log(f"updating {eco}…")
        results.append(update_ecosystem(eco, cache_dir, fetch=fetch))
    return write_manifest(cache_dir, results)


# ── load (scan-time, offline) ────────────────────────────────────────────────────────────
def load_corpus(cache_dir: str | Path | None = None) -> AdvisoryCorpus | None:
    """The cached malicious-package corpus, or None when no cache exists (→ inline-seed only).

    Reads only local files; never touches the network. Memoized by (dir, manifest mtime)."""
    cache_dir = Path(cache_dir or default_cache_dir())
    manifest_path = _manifest_path(cache_dir)
    try:
        mtime = manifest_path.stat().st_mtime
    except OSError:
        return None                    # no cache → caller falls back to the inline seed
    key = (str(cache_dir), mtime)
    if key not in _CORPUS_MEMO:
        _CORPUS_MEMO[key] = _build_corpus(cache_dir, manifest_path)
    return _CORPUS_MEMO[key]


def _int(value: Any) -> int:
    """A non-negative int from an untrusted manifest field: 0 for missing/None/bool/float/str/list.
    A corrupt count (`"malicious": null` from a partial write or tamper) must never crash the status
    report's `sum()` with a `TypeError` — it degrades to 0, like every other malformed field (#1137)."""
    return value if type(value) is int and value >= 0 else 0


def _ecosystems(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The manifest's per-ecosystem metadata, defensively normalized. A corrupt/tampered manifest
    may hold a non-dict `ecosystems`, or non-dict entries — coerce to `{}` / drop them so every
    consumer that iterates the cache degrades to the inline seed instead of crashing on a
    malformed cache (`.items()`/`.get()` on a non-dict)."""
    ecosystems = manifest.get("ecosystems")
    if not isinstance(ecosystems, dict):
        return {}
    return {eco: meta for eco, meta in ecosystems.items() if isinstance(meta, dict)}


def _stream_records(cache_dir: Path, manifest: dict[str, Any]):
    """Yield OsvRecords across the manifest's ecosystems, one JSONL line at a time — so a corpus of
    hundreds of thousands of records never exists as a single parsed list (bounded peak memory).

    Integrity gate: a records file is trusted only if its content hash matches the manifest. A
    mismatch means the cache was corrupted or tampered after `db update` — we skip it (falling back
    to the always-shipped inline seed) and warn loudly, never silently trusting bad data."""
    for eco, meta in _ecosystems(manifest).items():
        path = _records_path(cache_dir, eco)
        expected = meta.get("sha256")
        if expected and _file_sha256(path) != expected:
            print(f"⚠️  saw: advisory-cache integrity check FAILED for {eco} "
                  f"({path.name}) — ignoring it; run `saw db update`.", file=sys.stderr)
            continue
        try:
            fh = path.open(encoding="utf-8")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec = _record_from_json(raw)
                if rec is not None:
                    yield rec


def _schema_compatible(manifest: dict[str, Any]) -> bool:
    """True only if the on-disk manifest was written by *this* schema. An older `saw` used a
    different record layout (schema 1: `records/*.json`; schema 2: `records/*.jsonl`), so a
    schema mismatch is a benign *version skew* — NOT tampering — and must be diagnosed as such:
    the byte-level integrity gate would spuriously fire, crying "tampered" at every ecosystem."""
    return manifest.get("schema") == _SCHEMA


def _load_manifest(manifest_path: Path) -> dict[str, Any] | None:
    """Parse the manifest, or None if it's missing, unparseable, or not a JSON object. A corrupt
    manifest — including valid-JSON-but-not-a-dict (`null`, `[…]`, `42`, from a partial write or a
    tamper) — must degrade to 'no usable cache' (→ inline seed / fail-closed gate), never crash the
    scan on an `AttributeError` from `.get()` on a non-dict."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return manifest if isinstance(manifest, dict) else None


def _build_corpus(cache_dir: Path, manifest_path: Path) -> AdvisoryCorpus | None:
    manifest = _load_manifest(manifest_path)
    if manifest is None:
        return None
    if not _schema_compatible(manifest):
        # Old cache from a prior `saw` — a version upgrade, not corruption. Say so calmly (once,
        # thanks to the corpus memo) and fall back to the inline seed; do NOT run the integrity
        # gate, whose "tampered" alarm must stay reserved for a schema-matching cache (#1137).
        print(f"⚠️  saw: advisory cache is an older format (schema {manifest.get('schema')}; "
              f"this saw expects {_SCHEMA}) — using the inline seed. Run `saw db update` to rebuild.",
              file=sys.stderr)
        return None
    return AdvisoryCorpus.from_records(_stream_records(cache_dir, manifest))


# ── health / trust (saw db status, scan --require-db) ────────────────────────────────────
def _age_days(generated_at) -> int | None:
    if not generated_at:
        return None
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(str(generated_at))
    except (ValueError, TypeError):
        return None
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    return max(0, (now - dt).days)


def cache_status(cache_dir: str | Path | None = None) -> dict[str, Any]:
    """A health report for the advisory cache: presence, snapshot fingerprint, age, per-ecosystem
    counts, and a per-file integrity check (content hash vs. manifest). Reads only local files."""
    cache_dir = Path(cache_dir or default_cache_dir())
    manifest = _load_manifest(_manifest_path(cache_dir))
    if manifest is None:                       # absent, unparseable, or not a JSON object
        return {"present": False, "cache_dir": str(cache_dir)}
    ecosystems = _ecosystems(manifest)
    schema_compatible = _schema_compatible(manifest)
    # Only run the byte-level integrity gate on a schema-matching cache — the record filenames
    # differ across schemas, so hashing across a version skew yields spurious "mismatches" that
    # read as tampering. Callers branch on `schema_compatible` BEFORE `integrity_ok` (#1137).
    mismatches = [eco for eco, meta in ecosystems.items()
                  if meta.get("sha256")
                  and _file_sha256(_records_path(cache_dir, eco)) != meta["sha256"]] \
        if schema_compatible else []
    return {
        "present": True,
        "cache_dir": str(cache_dir),
        "schema": manifest.get("schema"),
        "schema_compatible": schema_compatible,
        "snapshot": manifest.get("snapshot"),
        "generated_at": manifest.get("generated_at"),
        "age_days": _age_days(manifest.get("generated_at")),
        "ecosystems": {eco: {k: _int(meta.get(k))
                             for k in ("count", "malicious", "vulnerabilities")}
                       for eco, meta in ecosystems.items()},
        "total_malicious": sum(_int(meta.get("malicious")) for meta in ecosystems.values()),
        "total_vulnerabilities": sum(_int(meta.get("vulnerabilities"))
                                     for meta in ecosystems.values()),
        # Fail-closed for naive callers: an incompatible cache is unusable, so integrity is not OK.
        # `mismatches` still lists only *genuine* hash mismatches (empty on pure schema skew).
        "integrity_ok": schema_compatible and not mismatches,
        "mismatches": mismatches,
    }


# ── on-disk record shape (normalized, minimal) ───────────────────────────────────────────
def _record_to_json(rec: OsvRecord) -> dict[str, Any]:
    return {"id": rec.id, "aliases": list(rec.aliases), "malicious": rec.malicious,
            "affected": [{"ecosystem": a.ecosystem, "name": a.name, "versions": sorted(a.versions),
                          "ranges": [{"type": r.type, "events": [list(e) for e in r.events]}
                                     for r in a.ranges]}
                         for a in rec.affected]}


def _affected_from_json(a: dict[str, Any]) -> OsvAffected | None:
    if not (isinstance(a, dict) and a.get("name")):
        return None
    versions = frozenset(a.get("versions", []) or [])
    ranges = tuple(
        OsvRange(str(r.get("type", "")), tuple(tuple(e) for e in (r.get("events", []) or [])))
        for r in (a.get("ranges", []) or []) if isinstance(r, dict) and r.get("events"))
    if not versions and not ranges:
        return None
    return OsvAffected(str(a.get("ecosystem", "")), str(a["name"]), versions, ranges)


def _record_from_json(raw: dict[str, Any]) -> OsvRecord | None:
    if not isinstance(raw, dict):
        return None
    affected = tuple(x for x in (_affected_from_json(a) for a in (raw.get("affected", []) or []))
                     if x is not None)
    if not affected:
        return None
    # `malicious` defaults True for back-compat with a #1120 cache (which stored malware only).
    return OsvRecord(id=str(raw.get("id", "")), aliases=tuple(raw.get("aliases", []) or []),
                     malicious=bool(raw.get("malicious", True)), affected=affected)
