<!-- What changed, and why. What someone using the release would observe. -->

Closes #

## Checklist

- [ ] Branched off a freshly fetched `origin/main`, and rebased on it — not merged.
- [ ] A bare `Closes #NNNN` above, on its own line. Partial work uses `Refs #NNNN` instead.
- [ ] `python -m unittest discover -s tests` passes, and the **Worm Guard** gate is green.
- [ ] User-visible change → a `CHANGELOG.md` `[Unreleased]` entry in this PR. No user-visible
      effect (a refactor, a pin bump) → no entry.
- [ ] That entry, and this description, describe **what a user observes** — not detector or rule
      internals, thresholds, the inputs an analysis keys on, or coverage gaps. Mechanism belongs in
      a private security report, never in a public body or commit message.
- [ ] Commits are signed, and carry no AI co-author trailer or assistant footer.
- [ ] Touching the security bot? The approach was agreed with the maintainer **before** this PR —
      those changes carry extra required checks. See [`SECURITY.md`](../SECURITY.md).

<!-- Merging is the maintainer's call; please don't self-merge. -->
