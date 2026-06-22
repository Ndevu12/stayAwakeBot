"""Scan targets (local & sandboxed-remote) behind one interface."""
from stayawakebot.security.targets.base import Target, ScanOptions
from stayawakebot.security.targets.local import LocalRepoTarget
from stayawakebot.security.targets.remote import RemoteRepoTarget

__all__ = ["Target", "ScanOptions", "LocalRepoTarget", "RemoteRepoTarget"]
