#!/usr/bin/env python3
"""Resolver registry — one entry per supported ecosystem (#1119, #1122, #1123).

Adding an ecosystem = write a `Resolver` and add it here; the store and matcher are untouched
(Open/Closed). The interface froze at the npm+PyPI pair (#1122); everything below is a new
resolver against that frozen surface.
"""
from __future__ import annotations

from stayawake.bots.security.dependencies.resolvers.base import Resolver
from stayawake.bots.security.dependencies.resolvers.npm import NpmResolver
from stayawake.bots.security.dependencies.resolvers.pypi import PyPiResolver
from stayawake.bots.security.dependencies.resolvers.cargo import CargoResolver
from stayawake.bots.security.dependencies.resolvers.go import GoResolver
from stayawake.bots.security.dependencies.resolvers.rubygems import RubyGemsResolver
from stayawake.bots.security.dependencies.resolvers.composer import ComposerResolver
from stayawake.bots.security.dependencies.resolvers.nuget import NuGetResolver
from stayawake.bots.security.dependencies.resolvers.maven import MavenResolver

RESOLVERS: tuple[Resolver, ...] = (
    NpmResolver(), PyPiResolver(), CargoResolver(), GoResolver(),
    RubyGemsResolver(), ComposerResolver(), NuGetResolver(), MavenResolver(),
)

__all__ = [
    "Resolver", "RESOLVERS",
    "NpmResolver", "PyPiResolver", "CargoResolver", "GoResolver",
    "RubyGemsResolver", "ComposerResolver", "NuGetResolver", "MavenResolver",
]
