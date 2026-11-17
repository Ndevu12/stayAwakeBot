"""The Rust workspace keeps the rebuild's rules."""

import json
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_DEPENDENCY_SECTIONS = ("dependencies", "dev-dependencies", "build-dependencies")


def _load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _workspace(root: Path) -> dict:
    return _load(root / "Cargo.toml")["workspace"]


def member_manifests(root: Path) -> dict[str, Path]:
    """Return each workspace member's package name with its manifest."""
    members = {}
    for pattern in _workspace(root).get("members", []):
        for manifest in sorted(root.glob(f"{pattern}/Cargo.toml")):
            members[_load(manifest)["package"]["name"]] = manifest
    return members


def separate_manifests(root: Path) -> dict[str, Path]:
    """Return each crate built outside the workspace with its manifest."""
    found = {}
    for folder in _workspace(root).get("exclude", []):
        manifest = root / folder / "Cargo.toml"
        found[_load(manifest)["package"]["name"]] = manifest
    return found


def _dependency_tables(manifest: dict) -> list[dict]:
    tables = [manifest.get(section, {}) for section in _DEPENDENCY_SECTIONS]
    for target in manifest.get("target", {}).values():
        tables += [target.get(section, {}) for section in _DEPENDENCY_SECTIONS]
    return tables


def _declared_dependencies(root: Path, manifest: dict) -> list[tuple[str, dict]]:
    """Return each (crate name, spec) a manifest declares, with inherited specs filled in."""
    shared = _workspace(root).get("dependencies", {})
    declared = []
    for table in _dependency_tables(manifest):
        for key, spec in table.items():
            spec = {"version": spec} if isinstance(spec, str) else dict(spec)
            if spec.pop("workspace", False):
                inherited = shared.get(key, {})
                inherited = {"version": inherited} if isinstance(inherited, str) else inherited
                spec = {**inherited, **spec}
            declared.append((spec.get("package", key), spec))
    return declared


def layering_problems(root: Path) -> list[str]:
    layers = _load(root / "crates" / "layers.toml")["layer"]
    members = member_manifests(root)
    problems = [f"{name} has no layer in crates/layers.toml" for name in members if name not in layers]
    for name, path in members.items():
        for dependency, spec in _declared_dependencies(root, _load(path)):
            if "path" not in spec or name not in layers or dependency not in layers:
                continue
            if layers[dependency] >= layers[name]:
                problems.append(f"{name} (layer {layers[name]}) depends on {dependency} "
                                f"(layer {layers[dependency]}); a crate depends only on lower layers")
    return problems


def direct_dependency_problems(root: Path) -> list[str]:
    record = _load(root / "crates" / "dependencies.toml")["direct"]
    problems = []
    manifests = {**member_manifests(root), **separate_manifests(root)}
    for name, path in manifests.items():
        for dependency, spec in _declared_dependencies(root, _load(path)):
            if "path" in spec:
                continue
            entry = record.get(dependency)
            if entry is None:
                problems.append(f"{name} uses {dependency}, which the dependency record does not name")
                continue
            if name not in entry.get("scope", [name]):
                problems.append(f"{name} uses {dependency}, which is recorded only for {entry['scope']}")
            if "version" in entry and spec.get("version") != entry["version"]:
                problems.append(f"{name} asks for {dependency} {spec.get('version')!r}; "
                                f"the record fixes {entry['version']!r}")
            if "default_features" in entry:
                chosen = spec.get("default-features", spec.get("default_features", True))
                if chosen != entry["default_features"]:
                    problems.append(f"{name} sets default features of {dependency} to {chosen}; "
                                    f"the record fixes {entry['default_features']}")
            if "features" in entry:
                for feature in spec.get("features", []):
                    if feature not in entry["features"]:
                        problems.append(f"{name} enables {dependency} feature {feature!r}, "
                                        "which the record does not allow")
    return problems


def locked_outside_crates(root: Path) -> set[str]:
    """Return the names of every outside crate in saw's lock files."""
    locks = [root / "Cargo.lock"] + [path.parent / "Cargo.lock" for path in separate_manifests(root).values()]
    names = set()
    for lock in locks:
        if lock.is_file():
            names |= {package["name"] for package in _load(lock).get("package", []) if "source" in package}
    return names


def locked_set_problems(root: Path) -> list[str]:
    recorded = set(_load(root / "crates" / "dependencies.toml")["locked"]["crates"])
    locked = locked_outside_crates(root)
    problems = [f"{name} is locked but not in the dependency record" for name in sorted(locked - recorded)]
    problems += [f"{name} is no longer locked; remove it from the record so the count goes down"
                 for name in sorted(recorded - locked)]
    return problems


def c_build_problems(root: Path) -> list[str]:
    record = _load(root / "crates" / "dependencies.toml")
    problems = []
    for name, path in member_manifests(root).items():
        package = _load(path)["package"]
        if (path.parent / "build.rs").exists() or "build" in package or "links" in package:
            problems.append(f"{name} has a build script or links a system library")
    for name in sorted(locked_outside_crates(root)):
        builds_c = name in record["c_build_crates"] or (
            name.endswith("-sys") and name not in record["sys_crates_without_c"])
        if builds_c and name not in record.get("c_build_exceptions", {}):
            problems.append(f"{name} builds C or links a system library")
    return problems


def unsafe_problems(root: Path) -> list[str]:
    allowed_in = _load(root / "crates" / "layers.toml")["unsafe_allowed_in"]
    problems = []
    if _workspace(root).get("lints", {}).get("rust", {}).get("unsafe_code") != "forbid":
        problems.append("the workspace does not forbid unsafe code")
    for name, path in member_manifests(root).items():
        lints = _load(path).get("lints", {})
        if name == allowed_in:
            if lints.get("rust", {}).get("unsafe_code") != "deny":
                problems.append(f"{name} must deny unsafe code outside the places it allows it")
        elif lints.get("workspace") is not True:
            problems.append(f"{name} does not take the workspace lints, so unsafe code is not forbidden")
    return problems


def version_problems(root: Path) -> list[str]:
    problems = []
    if "version" in _workspace(root).get("package", {}):
        problems.append("the workspace declares a version; the version is only the git tag")
    for name, path in member_manifests(root).items():
        if "version" in _load(path)["package"]:
            problems.append(f"{name} declares a version; the version is only the git tag")
    return problems


def licence_allowed(expression: str, licences: set[str], exceptions: set[str]) -> bool:
    """Return whether an SPDX licence expression is satisfied by the allowed licences."""
    tokens = re.findall(r"\(|\)|[^\s()]+", expression.replace("/", " OR "))
    position = 0

    def term() -> bool:
        nonlocal position
        token = tokens[position]
        position += 1
        if token == "(":
            allowed = either()
            position += 1
        else:
            allowed = token in licences
        if position < len(tokens) and tokens[position] == "WITH":
            allowed = allowed and tokens[position + 1] in exceptions
            position += 2
        return allowed

    def both() -> bool:
        nonlocal position
        allowed = term()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            allowed = term() and allowed
        return allowed

    def either() -> bool:
        nonlocal position
        allowed = both()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            allowed = both() or allowed
        return allowed

    return bool(tokens) and either()


def _outside_packages(manifest: Path) -> list[dict]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline", "--manifest-path", str(manifest)],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise unittest.SkipTest(
            f"cargo could not read the locked crates of {manifest.parent} offline; run "
            f"`cargo fetch --locked --manifest-path {manifest}` first. Error: {result.stderr.strip()[-300:]}")
    return [package for package in json.loads(result.stdout)["packages"] if package["source"]]


def licence_problems(root: Path) -> list[str]:
    record = _load(root / "crates" / "dependencies.toml")
    licences, exceptions = set(record["licences"]), set(record["licence_exceptions"])
    problems = []
    for manifest in [root / "Cargo.toml", *separate_manifests(root).values()]:
        for package in _outside_packages(manifest):
            if not licence_allowed(package.get("license") or "", licences, exceptions):
                problems.append(f"{package['name']} {package['version']} is licensed "
                                f"{package.get('license')!r}, which the record does not allow")
    return problems


class TheWorkspaceKeepsTheRules(unittest.TestCase):

    def test_crates_depend_only_on_lower_layers(self):
        self.assertEqual(layering_problems(REPO_ROOT), [])

    def test_only_recorded_outside_crates_are_used(self):
        self.assertEqual(direct_dependency_problems(REPO_ROOT), [])

    def test_the_locked_crates_match_the_record(self):
        self.assertEqual(locked_set_problems(REPO_ROOT), [])

    def test_nothing_builds_c(self):
        self.assertEqual(c_build_problems(REPO_ROOT), [])

    def test_unsafe_code_stays_in_the_platform_crate(self):
        self.assertEqual(unsafe_problems(REPO_ROOT), [])

    def test_no_crate_carries_a_version(self):
        self.assertEqual(version_problems(REPO_ROOT), [])

    def test_outside_crates_use_recorded_licences(self):
        if shutil.which("cargo") is None:
            self.skipTest("cargo is not installed, so the licences of the locked crates cannot be read")
        self.assertEqual(licence_problems(REPO_ROOT), [])


class EachRuleCatchesItsViolation(unittest.TestCase):
    """Each rule, broken in a copy of the workspace, is reported."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        for source in [REPO_ROOT / "Cargo.toml", REPO_ROOT / "Cargo.lock",
                       *REPO_ROOT.glob("crates/*.toml"), *REPO_ROOT.glob("crates/*/Cargo.toml"),
                       *(path.parent / name for path in separate_manifests(REPO_ROOT).values()
                         for name in ("Cargo.toml", "Cargo.lock"))]:
            target = self.root / source.relative_to(REPO_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def _edit(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def test_the_copy_starts_clean(self):
        for check in (layering_problems, direct_dependency_problems, locked_set_problems,
                      c_build_problems, unsafe_problems, version_problems):
            self.assertEqual(check(self.root), [], check.__name__)

    def test_an_upward_dependency_is_reported(self):
        self._edit("crates/saw-model/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\nsaw-engine = { path = "../saw-engine" }\n')
        self.assertEqual(layering_problems(self.root),
                         ["saw-model (layer 0) depends on saw-engine (layer 3); a crate depends only on lower layers"])

    def test_a_same_layer_dependency_is_reported(self):
        self._edit("crates/saw-act/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\nsaw-present = { path = "../saw-present" }\n')
        self.assertEqual(len(layering_problems(self.root)), 1)

    def test_a_crate_without_a_layer_is_reported(self):
        self._edit("crates/layers.toml", "saw-act = 4\n", "")
        self.assertIn("saw-act has no layer in crates/layers.toml", layering_problems(self.root))

    def test_an_unrecorded_crate_is_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[dependencies]\n", '[dependencies]\nfancy-regex = "0.14"\n')
        self.assertEqual(direct_dependency_problems(self.root),
                         ["saw-detect uses fancy-regex, which the dependency record does not name"])

    def test_a_renamed_unrecorded_crate_is_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\nregex = { package = "fancy-regex", version = "0.14" }\n')
        self.assertEqual(len(direct_dependency_problems(self.root)), 1)

    def test_a_crate_outside_its_scope_is_reported(self):
        self._edit("crates/saw-engine/Cargo.toml", "[dependencies]\n", '[dependencies]\ntokio = "1"\n')
        self.assertEqual(len(direct_dependency_problems(self.root)), 1)

    def test_a_forbidden_feature_is_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\nserde-saphyr = { version = "2.1", default-features = false, '
                   'features = ["deserialize", "include_fs"] }\n')
        self.assertEqual(direct_dependency_problems(self.root),
                         ["saw-detect enables serde-saphyr feature 'include_fs', which the record does not allow"])

    def test_default_features_left_on_are_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\ntoml = { version = "1", features = ["std", "parse"] }\n')
        self.assertEqual(len(direct_dependency_problems(self.root)), 1)

    def test_an_unpinned_unicode_version_is_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[dependencies]\n",
                   '[dependencies]\nunicode-properties = "0.1"\n')
        self.assertEqual(len(direct_dependency_problems(self.root)), 1)

    def test_a_workspace_inherited_crate_is_checked(self):
        self._edit("Cargo.toml", "[workspace.package]", '[workspace.dependencies]\nureq = "3"\n\n[workspace.package]')
        self._edit("crates/saw-act/Cargo.toml", "[dependencies]\n", "[dependencies]\nureq.workspace = true\n")
        self.assertEqual(direct_dependency_problems(self.root),
                         ["saw-act uses ureq, which the dependency record does not name"])

    def test_a_new_locked_crate_is_reported(self):
        self._append("Cargo.lock", '\n[[package]]\nname = "ring"\nversion = "0.17.14"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.assertEqual(locked_set_problems(self.root), ["ring is locked but not in the dependency record"])

    def test_a_crate_that_left_the_lock_must_leave_the_record(self):
        self._edit("crates/dependencies.toml", "crates = [\n", 'crates = [\n  "aaa-gone",\n')
        self.assertEqual(locked_set_problems(self.root),
                         ["aaa-gone is no longer locked; remove it from the record so the count goes down"])

    def test_a_c_building_crate_is_reported(self):
        self._append("Cargo.lock", '\n[[package]]\nname = "openssl-sys"\nversion = "0.9.0"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.assertIn("openssl-sys builds C or links a system library", c_build_problems(self.root))

    def test_a_build_script_is_reported(self):
        (self.root / "crates" / "saw-model" / "build.rs").write_text("fn main() {}\n")
        self.assertEqual(c_build_problems(self.root), ["saw-model has a build script or links a system library"])

    def test_a_crate_that_drops_the_workspace_lints_is_reported(self):
        self._edit("crates/saw-detect/Cargo.toml", "[lints]\nworkspace = true\n", "")
        self.assertEqual(len(unsafe_problems(self.root)), 1)

    def test_a_workspace_that_stops_forbidding_unsafe_is_reported(self):
        self._edit("Cargo.toml", 'unsafe_code = "forbid"', 'unsafe_code = "warn"')
        self.assertEqual(unsafe_problems(self.root), ["the workspace does not forbid unsafe code"])

    def test_a_crate_version_is_reported(self):
        self._edit("crates/saw-cli/Cargo.toml", 'name = "saw-cli"\n', 'name = "saw-cli"\nversion = "1.0.0"\n')
        self.assertEqual(version_problems(self.root),
                         ["saw-cli declares a version; the version is only the git tag"])

    def _append(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.write_text(path.read_text() + text)


class LicenceExpressions(unittest.TestCase):
    LICENCES = {"MIT", "Apache-2.0", "Unicode-3.0"}

    def test_expressions(self):
        cases = {
            "MIT": True,
            "MIT/Apache-2.0": True,
            "Unlicense OR MIT": True,
            "(MIT OR Apache-2.0) AND Unicode-3.0": True,
            "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT": True,
            "MIT AND GPL-3.0-only": False,
            "LGPL-2.1-or-later": False,
            "Apache-2.0 WITH Classpath-exception-2.0": False,
            "": False,
        }
        for expression, expected in cases.items():
            self.assertEqual(licence_allowed(expression, self.LICENCES, {"LLVM-exception"}), expected, expression)


if __name__ == "__main__":
    unittest.main()
