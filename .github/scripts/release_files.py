#!/usr/bin/env python3
"""Writes the files a saw release publishes for the clients that install it: the platform manifest,
the hash-locked requirements and the SBOM, each named for the release.

  release_files.py write <dist> <dependencies.lock> <CHANGELOG.md> <sbom.cdx.json> <out>
  release_files.py pins <dependencies.lock>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from email.parser import HeaderParser
from pathlib import Path

CONTRACT = 1
PROJECT = "stayawakebot"
_ARCH = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}
_WHEEL = re.compile(rf"^{PROJECT}-(?P<version>[^-]+)-py3-none-(?P<tag>.+)\.whl$")
_SDIST = re.compile(rf"^{PROJECT}-(?P<version>.+)\.tar\.gz$")


def platform_of(tag: str) -> dict:
    """Return the system, architecture, C library and minimum a wheel's platform tag names. Takes
    the tag. Raises ValueError for a tag that names no single system and architecture."""
    linux = re.fullmatch(r"(manylinux|musllinux)_(\d+)_(\d+)_(\w+)", tag)
    if linux and linux[4] in _ARCH:
        libc = "glibc" if linux[1] == "manylinux" else "musl"
        return {"os": "linux", "arch": _ARCH[linux[4]], "libc": libc, "minimum": f"{linux[2]}.{linux[3]}"}
    macos = re.fullmatch(r"macosx_(\d+)_(\d+)_(\w+)", tag)
    if macos and macos[3] in _ARCH:
        return {"os": "macos", "arch": _ARCH[macos[3]], "minimum": f"{macos[1]}.{macos[2]}"}
    windows = re.fullmatch(r"win_(\w+)", tag)
    if windows and windows[1] in _ARCH:
        return {"os": "windows", "arch": _ARCH[windows[1]]}
    raise ValueError(f"the wheel tag {tag} names no single system and architecture")


def is_security_release(changelog: str, version: str) -> bool:
    """Tell whether the changelog section for `version` has a Security heading. Takes the
    changelog text and the version."""
    section = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog,
                        flags=re.MULTILINE | re.DOTALL)
    return bool(section and re.search(r"^### Security\s*$", section[1], flags=re.MULTILINE))


def release_version(dist: Path) -> str:
    """Return the version every file in `dist` is built for. Takes the folder. Raises ValueError
    when there is no sdist or a wheel is for another version."""
    sdists = [match["version"] for match in map(_SDIST.match, (p.name for p in dist.iterdir())) if match]
    if len(sdists) != 1:
        raise ValueError(f"expected one {PROJECT} sdist in {dist}, found {len(sdists)}")
    version = sdists[0]
    for path in dist.glob("*.whl"):
        match = _WHEEL.match(path.name)
        if not match or match["version"] != version:
            raise ValueError(f"{path.name} is not a {PROJECT} {version} wheel")
    return version


def sha256_of(path: Path) -> str:
    """Return the SHA-256 of a file. Takes its path."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _requires_python(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError(f"{wheel.name} has no single METADATA")
        headers = HeaderParser().parsestr(archive.read(names[0]).decode("utf-8"))
    needed = headers.get("Requires-Python")
    if not needed:
        raise ValueError(f"{wheel.name} does not say which Python it needs")
    return needed


def manifest(dist: Path, version: str, changelog: str) -> dict:
    """Build the platform manifest. Takes the folder of built files, their version and the
    changelog text. Returns the manifest. Raises ValueError when there is no wheel, or two wheels
    for one system and architecture."""
    wheels = []
    for path in sorted(dist.glob("*.whl")):
        wheels.append({**platform_of(_WHEEL.match(path.name)["tag"]),
                       "requires_python": _requires_python(path),
                       "file": path.name, "sha256": sha256_of(path)})
    if not wheels:
        raise ValueError(f"no {PROJECT} wheel in {dist}")
    places = [(w["os"], w["arch"], w.get("libc")) for w in wheels]
    if len(set(places)) != len(places):
        raise ValueError("two wheels are built for one system and architecture")
    return {"contract": CONTRACT, "version": version,
            "security": is_security_release(changelog, version),
            "requirements_lock": lock_name(version), "sbom": sbom_name(version), "wheels": wheels}


def _requirements(lock_text: str) -> list[str]:
    joined = re.sub(r"\\\n", " ", lock_text)
    return [line.strip() for line in joined.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def pins(lock_text: str) -> list[str]:
    """Return each locked requirement as `name==version`, without its markers or hashes. Takes the
    lock text. Raises ValueError for a requirement that is not pinned to one version."""
    found = []
    for requirement in _requirements(lock_text):
        pinned = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)", requirement)
        if not pinned:
            raise ValueError(f"not pinned to one version: {requirement.split()[0]}")
        found.append(f"{pinned[1]}=={pinned[2]}")
    return found


def requirements_lock(dist: Path, version: str, dependencies: str) -> str:
    """Build the requirements lock: saw itself, by the hash of every built file, then its
    dependencies. Takes the folder of built files, their version and the dependency lock text.
    Returns the lock text. Raises ValueError for a dependency without a hash."""
    for requirement in _requirements(dependencies):
        if "--hash=sha256:" not in requirement:
            raise ValueError(f"no hash for {requirement.split()[0]}")
    built = sorted(p for p in dist.iterdir() if _WHEEL.match(p.name) or _SDIST.match(p.name))
    hashes = " \\\n".join(f"    --hash=sha256:{sha256_of(p)}" for p in built)
    return f"{PROJECT}=={version} \\\n{hashes}\n{dependencies.rstrip()}\n"


def lock_name(version: str) -> str:
    """Return the published name of the requirements lock. Takes the version."""
    return f"{PROJECT}-{version}.requirements.lock"


def sbom_name(version: str) -> str:
    """Return the published name of the SBOM. Takes the version."""
    return f"{PROJECT}-{version}.sbom.cdx.json"


def write(dist: Path, dependencies: Path, changelog: Path, sbom: Path, out: Path) -> list[Path]:
    """Write the manifest, the requirements lock and the SBOM into `out`. Takes the folder of built
    files, the dependency lock, the changelog, the SBOM and the output folder. Returns the files
    written."""
    version = release_version(dist)
    out.mkdir(parents=True, exist_ok=True)
    platforms = out / f"{PROJECT}-{version}.platforms.json"
    platforms.write_text(json.dumps(manifest(dist, version, changelog.read_text(encoding="utf-8")),
                                    indent=2) + "\n", encoding="utf-8")
    lock = out / lock_name(version)
    lock.write_text(requirements_lock(dist, version, dependencies.read_text(encoding="utf-8")),
                    encoding="utf-8")
    named_sbom = out / sbom_name(version)
    shutil.copyfile(sbom, named_sbom)
    return [platforms, lock, named_sbom]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    actions = parser.add_subparsers(dest="action", required=True)
    w = actions.add_parser("write", help="write the manifest, the requirements lock and the SBOM")
    for name in ("dist", "dependencies", "changelog", "sbom", "out"):
        w.add_argument(name, type=Path)
    p = actions.add_parser("pins", help="print each locked requirement as name==version")
    p.add_argument("dependencies", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "pins":
            print("\n".join(pins(args.dependencies.read_text(encoding="utf-8"))))
        else:
            for path in write(args.dist, args.dependencies, args.changelog, args.sbom, args.out):
                print(path)
    except (OSError, ValueError) as error:
        print(f"release_files: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
