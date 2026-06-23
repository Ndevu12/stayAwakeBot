"""Scan targets (local & sandboxed-remote) behind one interface."""
from security.targets.base import Target, ScanOptions
from security.targets.local import LocalRepoTarget
from security.targets.remote import RemoteRepoTarget

__all__ = ["Target", "ScanOptions", "LocalRepoTarget", "RemoteRepoTarget"]
