# Reporting a security issue

**Please do not open a public issue for a security report.**

Email **saw@ndevuspace.com**. If you would rather use GitHub, open a private security advisory from
the repository's **Security** tab.

Useful to include, as far as you have it:

- what the issue lets someone do
- the version you saw it on (`saw --version`)
- the steps or input that reproduce it
- whether it is already public anywhere

You will get a reply confirming receipt, and an indication of whether the report is accepted and what
happens next. Please give us a chance to ship a fix before describing the issue publicly.

## Scope

This project is a scanner. Both of the following are in scope, and the second is easy to overlook:

- a defect in the tool itself — anything that lets it be crashed, misled, or made to act outside what
  it documents
- **a way to make the tool report clean when it should not**, or to suppress a finding it would
  otherwise report

Reports about a repository that `saw` scanned — rather than about `saw` — belong with the owner of
that repository.

## Supported versions

Fixes land on the latest release. Older releases are not patched; upgrade to pick up a fix.
