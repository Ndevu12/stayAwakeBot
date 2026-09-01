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
        return self.via == "sudo"


def resolve(env=None) -> Operator | None:
    """The operator, or None when privilege was raised and the invoker cannot be established.

    None is not "fall back to `HOME`". Under `sudo` with a reset environment, `HOME` is root's,
    and acting on root's home while reporting success is the failure this exists to prevent.
    """
    env = os.environ if env is None else env
    raised = env.get("SUDO_UID") or env.get("SUDO_USER")
    if raised:
        record = _from_sudo(env)
        return record
    home = env.get("HOME")
    if not home:
        return None
    geteuid = getattr(os, "geteuid", None)
    return Operator(name=env.get("USER") or "", uid=geteuid() if geteuid else -1,
                    home=Path(home), via="environment")


def _from_sudo(env) -> Operator | None:
    uid = env.get("SUDO_UID")
    if uid and uid.isdigit():
        try:
            record = pwd.getpwuid(int(uid))
        except KeyError:
            record = None
        if record is not None:
            return Operator(name=record.pw_name, uid=record.pw_uid,
                            home=Path(record.pw_dir), via="sudo")
    name = env.get("SUDO_USER")
    if name:
        try:
            record = pwd.getpwnam(name)
        except KeyError:
            return None
        return Operator(name=record.pw_name, home=Path(record.pw_dir), via="sudo")
    return None


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
