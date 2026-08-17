# Gate CI

Stop an infected change from merging. For one repository step by step, see [gate a
repository](../tutorial/gate-a-repo.md); this is the operational view. Flags: [CLI
reference](../reference/cli/guard.md).

## Across a fleet

```bash
saw guard check --org your-org -f     # exit 1 if any repository lacks a required gate
saw guard setup --org your-org        # clone each repository and open a gate PR
saw guard drift --org your-org        # file/close one drift issue per repository behind its pin
```

`setup` installs the gate where there is none and otherwise bumps only the pinned action reference,
leaving the rest of the workflow untouched. It never pushes to a default branch, and it fails closed
if it cannot resolve the release to a SHA — offline, pass `--ref <sha|tag>`.

## Detection only

The installed gate opens a rolling fix PR on an infected verdict and stays **red until that PR is
merged**, so the check never passes on an unreviewed change. To detect without remediating, drop the
action's `remediate:` input and give the job read-only permissions — see the hand-written workflow in
the [project README](https://github.com/Ndevu12/stayAwakeBot#the-workflow-by-hand), which also lists the action's other
inputs. To run the scanner straight from this repository rather than from PyPI, reference the in-repo
composite instead — `uses: Ndevu12/stayAwakeBot/.github/actions/worm-scan@<SHA>`; both forms run the
same logic.

## In any other CI

`saw scan`'s exit code is the whole contract — no flag, no parsing:

```bash
pip install stayawakebot && saw scan
```

or with no Python at all:

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/ndevu12/stayawakebot saw scan /repo
```

`0` clean, `1` infected, `2` could-not-scan — see [exit codes](../reference/exit-codes.md). Upload
findings to code scanning with `--sarif`, and pass `--require-db` when the job must not lose advisory
coverage silently.

## Prove the gate is enforced

A gate that branch protection does not **require** is decoration. `saw guard check` checks the
requirement, not just the file; `saw audit --repo owner/name -f` reports it alongside the rest of a
repository's posture.
