# The Rust workspace

saw is being rebuilt here as one Rust program. The rules for the rebuild (what may change, the
branches, the merges) are in the `rust-rebuild` skill. This page covers the workspace itself.

## Crates and layers

| Layer | Crate | Holds |
| --- | --- | --- |
| 0 | `saw-model` | The shared vocabulary: requests, subjects, findings, verdicts, judgements |
| 1 | `saw-platform` | Everything asked of the operating system, and the only `unsafe` code |
| 2 | `saw-detect` | Reading content and matching signatures |
| 3 | `saw-engine` | The engine every command shares |
| 4 | `saw-domains`, `saw-act`, `saw-present` | Domain judges; carrying out a judgement; rendering it |
| 5 | `saw-cli` and, once promoted, `saw-mcp` and `saw-git-standin` | The programs |

A crate depends only on crates of a lower layer. `layers.toml` is the source; a new crate is placed
there before it is used. The editor session crate under `src/stayawake/bots/mcp/session` still
builds on its own until the rebuild promotes it.

## Where each capability lives

Running an external program, reaching the network, and building a regular expression each have one
home, named in `layers.toml`. Code anywhere else may not use them. The homes are where the safety of
each capability is enforced once, for every caller.

## Outside crates

`dependencies.toml` is the record of the outside crates saw may use, the features and versions
each is fixed to, the licences allowed, and every crate the lock files hold. Each crate is accepted
for now, not for good, and names the milestone where it is reviewed for replacement. The count only
goes down: adding a crate needs the maintainer's approval first, and a crate that leaves the lock
leaves the record.

## Changes that carry extra obligations

`saw-detect`, `saw-engine`, `saw-domains` and `saw-act` are the detection and remediation code.
They carry the same obligations as the Python security subtree: agree the approach with the
maintainer before opening the pull request.

## Building

```sh
cargo build --workspace                                                # this machine
cargo build --workspace --release --target x86_64-unknown-linux-musl   # static Linux, x86_64
cargo build --workspace --release --target aarch64-unknown-linux-musl  # static Linux, arm64
cargo build --workspace --release --target x86_64-pc-windows-gnullvm   # Windows, x86_64
cargo build --workspace --release --target aarch64-pc-windows-gnullvm  # Windows, arm64
```

Add a target once with `rustup target add <target>`. Linux builds need nothing beyond the Rust
toolchain. Windows builds need [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) with its `bin`
folder on `PATH`. A Windows binary needs only what Windows 10 and later provide.

## Checks

The Python test suite enforces the workspace rules, the same way it enforces the rules of the
Python code:

| Test | Holds |
| --- | --- |
| `tests/test_rust_workspace.py` | Layers, the dependency record and its count, licences, no C, `unsafe` only in the platform crate, no version in any manifest |
| `tests/test_rust_source_homes.py` | Each confined capability used only in its home |
| `tests/test_rust_locked_crates_advisories.py` | No locked crate has a known advisory (run `saw db update -e cargo` first) |

```sh
python -m unittest discover -s tests -p "test_rust_*.py"
```

Every check is also tested against a copy that breaks it, so a check that stops catching its
violation fails.

The data and documentation checks of the Python suite (signatures, wording, operator docs) keep
running unchanged.
