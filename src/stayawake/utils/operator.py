#!/usr/bin/env python3
"""Who a command acts for, when it is not who is running it.

A command that requires root is run through `sudo`, and `sudo` decides what `HOME` the program
sees. Some configurations pass the invoker's through; others set it to root's — `always_set_home`
on one distribution, an `env_reset` without `env_keep HOME` on the next. A control aimed at
`~/.node_modules` therefore lands in the operator's home on one machine and in `/var/root` on
another, and reads back as in place either way.

`sudo` records who invoked it, so this is answerable rather than a guess: `SUDO_UID` names the
account, the password database gives its home, and `HOME` is used only when nothing raised
privilege at all.
"""
from __future__ import annotations

import os
import pwd
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Operator:
    """The account a host-level command is acting for.

    `via` says how the answer was reached, so a caller can tell an established answer from a
    fallback and refuse on the difference if it must.
    """

    name: str
    uid: int
    home: Path
    via: str

    @property
    def raised(self) -> bool:
        """Whether privilege was raised to run this — i.e. `HOME` may not be the operator's."""
        return self.via == "raised"


def resolve(env=None) -> Operator | None:
    """The operator, or None when privilege was raised and the invoker cannot be established.

    None is not "fall back to `HOME`". Under `sudo` with a reset environment, `HOME` is root's,
    and acting on root's home while reporting success is the failure this exists to prevent.
    """
    env = os.environ if env is None else env
    if _raised(env):
        return _from_escalation(env)
    home = env.get("HOME")
    if not home:
        return None
    geteuid = getattr(os, "geteuid", None)
    return Operator(name=env.get("USER") or "", uid=geteuid() if geteuid else -1,
                    home=Path(home), via="environment")


_ESCALATION_UIDS = ("SUDO_UID", "PKEXEC_UID")
_ESCALATION_NAMES = ("SUDO_USER", "DOAS_USER")


def _raised(env) -> bool:
    """Whether this process is running as root on somebody else's behalf.

    Only the kernel answers it. An escalation marker is an ordinary variable any process can
    export, and reading its presence as proof let one line in a shell rc pick the account every
    location is graded against. `sudo -u <account>` sets the same markers without raising to root,
    and there that account IS who this acts for. The markers name the invoker; never that there is
    one.
    """
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _account_named_by_uid(env):
    """The account a uid marker names, when one of them names a real account.

    `str.isdigit` is true for characters `int` refuses (`'²'`), and catching only `KeyError` took
    that `ValueError` out through `acting_uid` into every caller.
    """
    for var in _ESCALATION_UIDS:
        uid = env.get(var)
        if not uid:
            continue
        try:
            return pwd.getpwuid(int(uid))
        except (ValueError, KeyError, OverflowError):
            continue
    return None


def _account_named_by_name(env):
    for var in _ESCALATION_NAMES:
        name = env.get(var)
        if not name:
            continue
        try:
            return pwd.getpwnam(name)
        except KeyError:
            continue
    return None


def _from_escalation(env) -> Operator | None:
    """The invoking account, when every marker present agrees on which one it is.

    `sudo` and `doas` write the uid and the name from one decision, so two that disagree are
    evidence the environment was not built by one. Refused rather than resolved to whichever was
    read first.
    """
    by_uid = _account_named_by_uid(env)
    by_name = _account_named_by_name(env)
    if by_uid is not None and by_name is not None and by_uid.pw_uid != by_name.pw_uid:
        return None
    record = by_uid or by_name
    if record is None:
        return None
    return Operator(name=record.pw_name, uid=record.pw_uid,
                    home=Path(record.pw_dir), via="raised")


def acting_uid(env=None) -> int:
    """The uid a denial belongs to when it is not root's.

    Under `sudo` the effective uid is 0, so comparing an owner against it answers "is this root's"
    twice and never "is this the operator's" — which is how the only path that raises a lock from
    the operator to root became unreachable.
    """
    who = resolve(env)
    if who is not None and who.uid >= 0:
        return who.uid
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else -1
