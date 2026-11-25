#!/usr/bin/env python3
"""A directory denial on Windows: the account cannot add or remove anything in it."""
from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path

from stayawake.utils.systembin import system_binary, windows_system_root

ADMINISTRATORS = "S-1-5-32-544"
SYSTEM = "S-1-5-18"

_FILE_ADD_FILE = 0x0002
_FILE_ADD_SUBDIRECTORY = 0x0004
_FILE_DELETE_CHILD = 0x0040
_DELETE = 0x00010000
_WRITE_BITS = _FILE_ADD_FILE | _FILE_ADD_SUBDIRECTORY | _FILE_DELETE_CHILD | _DELETE
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_ALL = 0x10000000
_GENERIC_WRITE = 0x40000000
_CHANGES_A_FOLDER = (_FILE_ADD_FILE | _FILE_ADD_SUBDIRECTORY | _FILE_DELETE_CHILD | _WRITE_DAC | _WRITE_OWNER
                     | _GENERIC_ALL | _GENERIC_WRITE)
_ALLOWED = 0
_DENIED = 1
_INHERIT_ONLY = 0x08
OWNER_RIGHTS = "S-1-3-4"
_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x4
_OWNER_SECURITY_INFORMATION = 0x1
_ACL_SIZE_INFORMATION = 2


def administrator() -> bool:
    """Tell whether this process is an administrator. Returns the answer, False when it cannot be
    told."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def grade(owner: str | None, acting: str | None) -> str:
    """Grade who holds a denial. Takes the owner's account and the account saw is acting for.
    Returns `root` when an administrator holds it, `self` when the acting account does, and
    `other` otherwise."""
    if not owner:
        return "other"
    folded = owner.upper()
    if folded in (SYSTEM, ADMINISTRATORS):
        return "root"
    if acting and folded == acting.upper():
        return "self"
    return "other"


def _icacls() -> str | None:
    """Find the system's access-control program. Returns its path, or None when it is not there."""
    return system_binary((os.path.join(windows_system_root(), "System32", "icacls.exe"),))


def _advapi():
    """Load the security library. Returns it, or None when this system has none."""
    try:
        return ctypes.WinDLL("advapi32", use_last_error=True)
    except (AttributeError, OSError):
        return None


def _sid_text(adv, sid) -> str | None:
    """Render `sid` as text. Takes the security library and the sid. Returns the text, or None."""
    rendered = ctypes.c_void_p()
    if not adv.ConvertSidToStringSidW(sid, ctypes.byref(rendered)) or not rendered.value:
        return None
    try:
        return ctypes.wstring_at(rendered.value)
    finally:
        ctypes.windll.kernel32.LocalFree(rendered)


def current_sid() -> str | None:
    """The account this process is running as. Returns its sid, or None when it cannot be read."""
    adv = _advapi()
    if adv is None:
        return None
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        return None
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    adv.OpenProcessToken.argtypes = (ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
    adv.GetTokenInformation.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                        ctypes.POINTER(ctypes.c_ulong))
    token = ctypes.c_void_p()
    try:
        if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return None
        needed = ctypes.c_ulong()
        adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if needed.value <= 0:
            return None
        buf = ctypes.create_string_buffer(needed.value)
        if not adv.GetTokenInformation(token, 1, buf, needed, ctypes.byref(needed)):
            return None
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p)).contents
        return _sid_text(adv, sid)
    except (OSError, AttributeError):
        return None
    finally:
        if token.value:
            kernel.CloseHandle(token)


def owner_sid(path: Path) -> str | None:
    """Read who owns `path`. Takes the path. Returns their sid, or None when it cannot be read."""
    adv = _advapi()
    if adv is None:
        return None
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        if adv.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION,
                                     ctypes.byref(owner), None, None, None,
                                     ctypes.byref(descriptor)) != 0:
            return None
        return _sid_text(adv, owner)
    except (OSError, AttributeError):
        return None
    finally:
        if descriptor.value:
            ctypes.windll.kernel32.LocalFree(descriptor)


def held_owner_sid(handle: int) -> str | None:
    """Read who owns an open file, folder or link. Takes its handle, opened with READ_CONTROL. Returns
    their sid, or None when it cannot be read."""
    adv = _advapi()
    if adv is None:
        return None
    owner = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        if adv.GetSecurityInfo(ctypes.c_void_p(handle), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION,
                               ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)) != 0:
            return None
        return _sid_text(adv, owner)
    except (OSError, AttributeError):
        return None
    finally:
        if descriptor.value:
            ctypes.windll.kernel32.LocalFree(descriptor)


def trusted_owner(owner: str | None, acting: str | None, elevated: bool) -> bool:
    """Tell whether an owner is one a write may trust: the system or the Administrators group, and,
    unless this process runs elevated, the account saw is acting for. Takes the owner's sid, the acting
    account's and whether this process runs elevated. Returns the answer."""
    graded = grade(owner, acting)
    return graded == "root" or (graded == "self" and not elevated)


def others_may_write(handle: int, trusted: set[str]) -> bool:
    """Tell whether anyone but the trusted accounts may add or delete entries in an open folder, or
    change who may or who owns it. Takes its handle, opened with READ_CONTROL, and the trusted
    accounts' sids. Returns the answer, True when its permissions cannot be read."""
    adv = _advapi()
    if adv is None:
        return True
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        if adv.GetSecurityInfo(ctypes.c_void_p(handle), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                               None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) != 0:
            return True
        if not dacl.value:
            return True
        allowed = {sid.upper() for sid in trusted}
        for entry in _aces(adv, dacl):
            if entry is None:
                return True
            ace_type, flags, mask, sid = entry
            if flags & _INHERIT_ONLY or ace_type == _DENIED:
                continue
            if ace_type != _ALLOWED:
                return True
            if mask & _CHANGES_A_FOLDER and (_sid_text(adv, ctypes.c_void_p(sid)) or "").upper() not in allowed:
                return True
        return False
    except (OSError, AttributeError, ValueError):
        return True
    finally:
        if descriptor.value:
            ctypes.windll.kernel32.LocalFree(descriptor)


class _AclSize(ctypes.Structure):
    _fields_ = [("AceCount", ctypes.c_ulong), ("AclBytesInUse", ctypes.c_ulong),
                ("AclBytesFree", ctypes.c_ulong)]


class _AceHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", ctypes.c_ushort)]


def _aces(adv, dacl):
    """Walk the entries of a permissions list. Takes the security library and the list. Yields each
    entry's type, flags, rights and the address of its account's sid, or None for an entry that cannot
    be read. Raises `OSError` when the list's size cannot be read."""
    size = _AclSize()
    if not adv.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), _ACL_SIZE_INFORMATION):
        raise OSError("the permissions list could not be read")
    for index in range(size.AceCount):
        ace = ctypes.c_void_p()
        if not adv.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
            yield None
            continue
        header = _AceHeader.from_address(ace.value)
        if header.AceSize < 8:
            yield None
            continue
        yield header.AceType, header.AceFlags, ctypes.c_uint32.from_address(ace.value + 4).value, ace.value + 8


def write_denied(path: Path, sid_text: str) -> bool:
    """Tell whether `sid_text` is denied from adding or removing anything in `path`. Takes the path
    and the account. Returns the answer, False when the denial cannot be read."""
    if not sid_text:
        return False
    adv = _advapi()
    if adv is None:
        return False
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    try:
        if adv.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION,
                                     None, None, ctypes.byref(dacl), None,
                                     ctypes.byref(descriptor)) != 0 or not dacl.value:
            return False
        for entry in _aces(adv, dacl):
            if entry is None:
                continue
            ace_type, _flags, mask, sid = entry
            if ace_type != _DENIED or not mask & _WRITE_BITS:
                continue
            text = _sid_text(adv, ctypes.c_void_p(sid))
            if text and text.upper() == sid_text.upper():
                return True
        return False
    except (OSError, AttributeError, ValueError):
        return False
    finally:
        if descriptor.value:
            ctypes.windll.kernel32.LocalFree(descriptor)


def _clear_readonly(path: str) -> None:
    """Clear the read-only attribute on `path` so its access control can be written. Takes the path.
    Returns nothing."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x10)
    except (AttributeError, OSError):
        return


def _run_icacls(argv: list[str], *, run, binary: str | None) -> bool:
    """Run the access-control program. Takes its arguments, the runner and an optional binary.
    Returns whether it accepted them."""
    if argv:
        _clear_readonly(argv[0])
    tool = binary or _icacls()
    if tool is None:
        return False
    try:
        done = run([tool, *argv], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def deny_writes(path: Path, sid_text: str, *, run=subprocess.run, binary: str | None = None) -> bool:
    """Deny `sid_text` from adding or removing anything in `path`. Takes the path, the account, the
    runner and an optional binary. Returns whether a read-back shows the denial."""
    if not sid_text:
        return False
    if not _run_icacls([str(path), "/deny", f"*{sid_text}:(OI)(CI)(WD,AD,DC,DE)", "/C"],
                       run=run, binary=binary):
        return False
    return write_denied(path, sid_text)


def allow_writes(path: Path, sid_text: str, *, run=subprocess.run, binary: str | None = None) -> bool:
    """Remove the denial that stops `sid_text` writing in `path`. Takes the path, the account, the
    runner and an optional binary. Returns whether a read-back shows it gone."""
    if not sid_text:
        return False
    if not _run_icacls([str(path), "/remove:d", f"*{sid_text}", "/C"], run=run, binary=binary):
        return False
    return not write_denied(path, sid_text)


def give_to_administrators(path: Path, *, run=subprocess.run, binary: str | None = None) -> bool:
    """Make an administrator the owner of `path`. Takes the path, the runner and an optional binary.
    Returns whether a read-back shows that owner."""
    return give_to(path, ADMINISTRATORS, run=run, binary=binary)


def give_to(path: Path, sid_text: str, *, run=subprocess.run, binary: str | None = None) -> bool:
    """Make an account the owner of `path`. Takes the path, the account, the runner and an optional
    binary. Returns whether a read-back shows that owner."""
    if not sid_text:
        return False
    if not _run_icacls([str(path), "/setowner", f"*{sid_text}", "/C"], run=run, binary=binary):
        return False
    owner = owner_sid(path)
    return owner is not None and owner.upper() == sid_text.upper()
