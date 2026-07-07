#!/usr/bin/env python3
"""Resolver registry — one entry per supported ecosystem (#1119).

Adding an ecosystem = write a `Resolver` and add it here; the store and matcher are
untouched (Open/Closed). Phase 3 (#1122/#1123) grows this tuple to PyPI, Go, Rust, Ruby,
Composer, .NET and Maven.
"""
from __future__ import annotations

from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.dependencies.resolvers.npm import NpmResolver

RESOLVERS: tuple[Resolver, ...] = (NpmResolver(),)

__all__ = ["Resolver", "NpmResolver", "RESOLVERS"]
