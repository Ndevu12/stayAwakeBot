---
description: What removing a dependency saw names as compromised changes in your project, what it may break, and what to do before and after.
---

# Remove a compromised dependency

When a scan flags a dependency, `saw` ends with the compromised versions and the command that
removes each package. It never names a version to install: the replacement is yours to choose.
`saw` does not run these commands or change your manifests for you.

```sh
# known-malicious — remove and replace these
#   evil-pkg@1.2.3
npm uninstall evil-pkg

# affected by an advisory — move off these
#   lodash@4.17.20
npm uninstall lodash
```

## Before you remove a known-malicious package

A known-malicious version is malware. If it was ever installed on this machine, its code may
already have run here, and removing it does not undo what it did.

**Do not rotate any credential yet.** Run `saw audit` first and work in the order it gives:
changing a password or token while that code still runs hands it the new one, and can set off code
that deletes your files. See [audit a machine](audit-a-machine.md).

In a repository, `saw fix` asks before it removes a known-malicious package your project declares.
See [fix findings](fix-findings.md).

## What each command changes

Run it in the project, or the environment, the package belongs to.

| Command | What it changes |
| --- | --- |
| `npm uninstall <package>` | Removes it from `package.json`, the lockfile and `node_modules`. |
| `pip uninstall -y <package>` | Removes it from the Python environment active in your shell. Your requirements files and `pyproject.toml` still list it. |
| `gem uninstall <package>` | Removes the installed gem. Your `Gemfile` still lists it. |
| `cargo remove <package>` | Removes it from `Cargo.toml`. |
| `composer remove <package>` | Removes it from `composer.json`, `composer.lock` and `vendor/`. |
| `dotnet remove package <package>` | Removes it from the project file. |
| `go mod edit -droprequire <package> && go mod tidy` | Removes it from `go.mod`. `go mod tidy` adds it back while your code still imports it. |

Where a file still lists the package, remove it there too, or your next install brings it back.

## What it may break

- **Code that uses the package** fails to build, start or pass its tests until you replace the
  package or remove that code.
- **A package another one brings in stays installed.** `npm uninstall` removes only what your
  `package.json` declares; for anything else it reports "up to date". Find which of your
  dependencies brings it in, with `npm ls <package>` for npm, and move off that one.
- **A version affected by an advisory** is usually best upgraded rather than removed. The advisory
  linked under the finding in the report names the versions that fix it.

## After you remove it

1. Install the replacement you chose, then rebuild and run your tests.
2. Run `saw scan .` again. It says whether the project is clean.
