"""Answer scan and audit questions on one stream, and remember an unchanged folder."""
from __future__ import annotations

import contextlib
import io
import json
import sys
from typing import TextIO

from stayawake.bots.mcp.identity import files_identity
from stayawake.utils import exitcodes

_AUDIT_VERDICTS = ("safe", "safe-once-confirmed", "unsafe", "incomplete")


def scan_verdict(document: dict | None) -> str:
    """Name the verdict of a scan document. Takes the document. Returns clean, infected,
    suspicious, residue, or not verified when the document is absent or a target was not read."""
    if not isinstance(document, dict) or "schema_version" not in document or document.get("any_error"):
        return "not verified"
    if document.get("any_infected"):
        return "infected"
    if document.get("any_suspicious"):
        return "suspicious"
    if document.get("any_residue"):
        return "residue"
    return "clean"


def audit_verdict(document: dict | None) -> str:
    """Name the verdict of an audit document. Takes the document. Returns its rotation verdict,
    or not verified when the document is absent or has none."""
    if not isinstance(document, dict):
        return "not verified"
    rotation = document.get("rotation")
    word = rotation.get("verdict") if isinstance(rotation, dict) else None
    if word in _AUDIT_VERDICTS:
        return word
    return "not verified"


def _scan_document(paths: list[str]) -> dict | None:
    """Scan these paths. Takes them. Returns the scan document, or None when it was not produced."""
    from stayawake.bots.security.service.run import scan

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        scan(paths=paths, json_out=True, no_stream=True)
    text = buffer.getvalue().strip()
    if not text:
        return None
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(document, dict) or "schema_version" not in document:
        return None
    return document


def _audit_document() -> dict | None:
    """Audit this machine. Returns the audit document, or None when the audit did not finish."""
    from stayawake.bots.security import hygiene
    from stayawake.lib.auth import resolve_token
    from stayawake.utils.json_documents import versioned

    try:
        with contextlib.redirect_stdout(io.StringIO()):
            token, _ = resolve_token()
            outcomes = [hygiene.run_check(label, check)
                        for label, check in hygiene.audit_checks(None, token, "main",
                                                                 verify_artifacts=False)]
            document = versioned("audit", hygiene.as_document(outcomes))
    except Exception:
        return None
    if not isinstance(document, dict) or "schema_version" not in document:
        return None
    return document


class Session:
    """The answers one running saw remembers."""

    def __init__(self) -> None:
        self._remembered: dict[str, dict] = {}
        self._audit: dict | None = None

    def scan_paths(self, paths: object) -> dict:
        """Scan these paths, reusing an answer when they are unchanged. Takes the paths. Returns
        the verdict and, when a document was produced, that document."""
        if (not isinstance(paths, list) or not paths
                or any(not isinstance(path, str) or path == "" for path in paths)):
            return {"verdict": "not verified"}
        identity = files_identity(paths)
        if identity is not None and identity in self._remembered:
            return self._remembered[identity]
        document = _scan_document(paths)
        verdict = scan_verdict(document)
        answer = {"verdict": verdict}
        if isinstance(document, dict):
            answer["document"] = document
        if verdict != "not verified" and identity is not None:
            self._remembered[identity] = answer
        return answer

    def verdict(self, path: object) -> dict:
        """Report the verdict for one path. Takes the path. Returns the same answer as scanning it."""
        if not isinstance(path, str):
            return {"verdict": "not verified"}
        return self.scan_paths([path])

    def audit(self, again: bool = False) -> dict:
        """Report this machine's audit. Takes whether to run it again. Returns the verdict and,
        when a document was produced, that document. A later call returns the same answer until
        `again` is set."""
        if self._audit is not None and not again:
            return self._audit
        document = _audit_document()
        verdict = audit_verdict(document)
        answer = {"verdict": verdict}
        if isinstance(document, dict):
            answer["document"] = document
        if verdict != "not verified":
            self._audit = answer
        return answer


def handle(session: Session, request: dict) -> dict:
    """Answer one request. Takes the session and the request. Returns the JSON-RPC reply."""
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params")
    if not isinstance(params, dict):
        params = {}
    try:
        if method == "scan":
            body = session.scan_paths([params.get("path")])
        elif method == "scan_files":
            paths = params.get("paths")
            body = session.scan_paths(paths if isinstance(paths, list) else [])
        elif method == "verdict":
            body = session.verdict(params.get("path"))
        elif method == "audit":
            body = session.audit(bool(params.get("again")))
        else:
            body = {"verdict": "not verified"}
    except Exception:
        body = {"verdict": "not verified"}
    if body.get("verdict") == "not verified" and "document" not in body:
        return {"jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32000, "message": "not verified"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": body}


def _write(stdout: TextIO, payload: dict) -> bool:
    """Write one answer. Takes the stream and the answer. Returns whether it was written."""
    try:
        stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
        stdout.flush()
    except (OSError, TypeError, ValueError):
        return False
    return True


def serve(stdin: TextIO, stdout: TextIO) -> int:
    """Answer requests from `stdin` until it closes. Takes the streams. Returns when the stream
    closes, or when an answer cannot be written."""
    session = Session()
    while True:
        line = stdin.readline()
        if line == "":
            return exitcodes.CLEAN
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            if not _write(stdout, {"id": None, "verdict": "not verified"}):
                return exitcodes.INCOMPLETE
            continue
        if not isinstance(request, dict):
            if not _write(stdout, {"id": None, "verdict": "not verified"}):
                return exitcodes.INCOMPLETE
            continue
        if not _write(stdout, handle(session, request)):
            return exitcodes.INCOMPLETE


def main() -> int:
    """Answer on this process's standard streams. Returns when they close."""
    return serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    sys.exit(main())
