"""Scan targets (local & sandboxed-remote) behind one interface."""
from stayawake.bots.security.targets.base import Target, ScanOptions
from stayawake.bots.security.targets.local import LocalRepoTarget
from stayawake.bots.security.targets.remote import RemoteRepoTarget

__all__ = ["Target", "ScanOptions", "LocalRepoTarget", "RemoteRepoTarget"]
