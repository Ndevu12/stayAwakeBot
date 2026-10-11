#!/usr/bin/env python3
"""Read a GitHub Actions workflow's triggers and jobs, every field checked for its type."""
from __future__ import annotations


def triggers(doc: dict) -> set[str]:
    """Name the events a workflow runs on. Takes the parsed workflow. Returns the event names."""
    raw = doc.get("on")
    if raw is None:
        raw = doc.get(True)
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, (list, dict)):
        return {t for t in raw if isinstance(t, str)}
    return set()


def jobs(doc: dict) -> dict:
    """List a workflow's jobs by id, in the order the workflow gives them. Takes the parsed workflow.
    Returns each job that is a mapping, by its id."""
    held = doc.get("jobs")
    return {job_id: job for job_id, job in held.items() if isinstance(job, dict)} if isinstance(held, dict) else {}
