#!/usr/bin/env python3
"""Pick how this system holds folders open: by descriptor on macOS and Linux, by held handles on
Windows. Each gives `open_folder`, `hold`, `is_another_disk` and a `Folder` with the same methods."""
from __future__ import annotations

import os

if os.name == "nt":
    from stayawake.utils.folders_windows import Folder, hold, is_another_disk, open_folder
else:
    from stayawake.utils.folders_posix import Folder, hold, is_another_disk, open_folder

__all__ = ["Folder", "hold", "is_another_disk", "open_folder"]
