---
description: What a cached GitHub credential risks, how to judge it by lifetime, scope and whether it can be copied, and how to remove one you do not use.
---

# Credential hygiene: cached GitHub credentials

A GitHub token in your OS keychain is normal: the keychain is an encrypted store and the recommended
place for it. What decides the risk is the token's lifetime, its scope, and whether a process running
as you can copy it. Most developers authenticate in several ways (SSH, HTTPS with a token, `gh`). Keep
each one low-risk, and remove only the ones you do not use.

This page explains the `cached-github-keychain` and `git-credentials-plaintext` findings of
[`saw audit`](../reference/cli/audit.md). When the keychain or `~/.git-credentials` could not be read,
the audit reports that it was not read; unlock or open it and run the audit again.

## The threat

Supply-chain worms run as your user, through an `npm` install script, an editor task that runs when a
folder opens, or an agent hook. From there they read what you can read without authenticating again:
an unlocked keychain, `~/.ssh`, the `gh` token. They look for a working GitHub credential to push
with. A credential has to be stored to be usable, so what matters is how much a copy of it can do, and
whether it can be copied at all.

## What determines the risk

- A credential is kept somewhere to work: git over HTTPS in the keychain, `gh` in the keychain, SSH
  in `~/.ssh`.
- The OS keychain is encrypted at rest, and a better place than a plaintext `~/.git-credentials`
  (`credential.helper store`).
- A token in use is not safer for it: a working token is the one worth copying.

| Property | Lower risk | Higher risk |
| --- | --- | --- |
| **Lifetime** | short-lived or auto-refreshed (minutes to hours) | a token that never expires |
| **Scope** | least privilege, one repository | `repo` + `admin:*` + `gist` |
| **Copyable** | a hardware-backed `sk-`/FIDO key | a bearer token or a plain key file |

A bearer token can be replayed from any machine, so a long-lived, broadly scoped one is the credential
to deal with first. `saw audit` reports where a token is kept; use the table to judge its lifetime and
scope.

## Deciding what to do

Using more than one way to authenticate is normal: SSH for some repositories, HTTPS with a token for
others (SSO, CI, containers, networks that block port 22), `gh` for the API. For each credential, the
question is whether you use it.

```
Do you use HTTPS auth for any project?
├─ Yes → keep it, and make it short-lived, least-scope and hardware-backed where you can.
├─ No, it is a leftover → remove it (below).
└─ It is your only path → set up another path first, check it works, then remove it.
```

## Ways to authenticate

Combine these as your projects need, strongest first:

1. **Hardware-backed SSH key** (`ed25519-sk`, a FIDO security key) with `git@github.com` remotes. It
   signs, and cannot be copied.
   - `ssh-keygen -t ed25519-sk -C "yubikey-github"`, add the `.pub` to GitHub, and use SSH remotes.
2. **`gh` as git's credential helper**: `gh auth setup-git`. git uses `gh`'s short-lived,
   auto-refreshed token, and `gh auth logout` revokes it.
3. **SSH key in `~/.ssh`**, protected by a passphrase and loaded into `ssh-agent`.
4. **In-memory HTTPS cache**: `git config --global credential.helper 'cache --timeout=3600'`. It is
   kept in memory until the timeout or a restart.

To see what you use today:

```bash
ssh -T git@github.com                 # "Hi <you>!" means SSH works
gh auth status                        # whether gh is logged in
git remote -v                         # git@github.com is SSH; https:// uses a token
git config --get-all credential.helper
```

## Removing a cached token you do not use

**1. Find where the helper is set.**

```bash
git config --show-origin --get-all credential.helper
```

On macOS this is often the Command Line Tools default,
`/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig`. It is a read-only system file, so
`git config --unset` leaves it in place.

**2. Clear the inherited helper** by adding an empty value to your global config:

```bash
git config --global --add credential.helper ""
```

**3. Delete the token** with the command `saw audit` prints for your platform.

**4. Check the result.**

```bash
printf 'protocol=https\nhost=github.com\n\n' | GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= GCM_INTERACTIVE=never git credential fill
ssh -T git@github.com
```

The first command ends with "could not read Username" when no helper holds a token. The second
confirms you can still authenticate over SSH.

## What removal leaves in place

A developer machine usually holds three separate github.com credentials:

| Store | Used by | Removed by the steps above |
| --- | --- | --- |
| git's HTTPS token (macOS Keychain, Linux Secret Service, Windows Credential Manager) | git over HTTPS | yes |
| `gh`'s token | the `gh` CLI | no; `gh auth logout` removes it |
| SSH keys (`~/.ssh/id_*`) | git over SSH | no |

Keeping `gh`'s short-lived token is a good end state.

## If the host may be compromised

This page covers routine hygiene. If `saw audit` reports persistence, follow the incident order
instead: run `saw harden`, remove the persistence, rebuild, and rotate credentials last. Rotating
while persistence is running can trigger a home-directory wiper.

## Checklist

- [ ] I know how this machine authenticates to GitHub: SSH, `gh` as git's helper, or an HTTPS token.
- [ ] The credential I remove is one I do not use, or I have set up its replacement first.
- [ ] The tokens I keep are short-lived and least-scope, or I use a hardware-backed key.
- [ ] After removing a token, git no longer finds one and I can still authenticate.
- [ ] I know the `gh` token and SSH keys are separate, and stay in place.
