#!/usr/bin/env python3
"""Pick how this system holds folders open: by descriptor on macOS and Linux, by held handles on
Windows. Each gives the same functions and a `Folder` with the same methods."""
from __future__ import annotations

import os

if os.name == "nt":
    from stayawake.utils.folders_windows import (Folder, close_to_writes, give_to, give_to_root, hold,
                                                 hold_entry, is_another_disk, open_folder,
                                                 open_to_its_owner, owner_of, reachable_by)
else:
    from stayawake.utils.folders_posix import (Folder, close_to_writes, give_to, give_to_root, hold,
                                               hold_entry, is_another_disk, open_folder,
                                               open_to_its_owner, owner_of, reachable_by)

__all__ = ["Folder", "close_to_writes", "give_to", "give_to_root", "hold", "hold_entry",
           "is_another_disk", "open_folder", "open_to_its_owner", "owner_of", "reachable_by"]
