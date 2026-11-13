#!/usr/bin/env python3
"""Posture domain: configuration, container and CI hygiene detectors.

A cohesive home for findings about committed credentials, insecure container and CI settings, and
secrets reachable in logs — distinct from the worm/supply-chain matchers, reusing the shared scan
engine (`Matcher`/`Finding`/REGISTRY). Each matcher is registered in `matchers/__init__.py` and
driven by its own data signatures, so the caller composes it like any other.
"""
from __future__ import annotations
