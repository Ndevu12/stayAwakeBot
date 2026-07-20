# Credential hygiene: cached GitHub credentials and the worm threat model

> **TL;DR** — A GitHub token cached in your OS keychain is **not** automatically a vulnerability; the
> keychain is a recommended, encrypted store. What matters is the token's **lifetime, scope, and
> whether it can be copied** by a process running as you. It is normal to use **several** auth methods
> across projects (SSH, HTTPS + PAT, `gh`) — the goal is **not** to collapse to one, but to make
> **each** credential you keep low-risk, and to remove only the ones you genuinely don't use. Deleting
> a credential path you actually rely on just logs you out.

This page backs the `cached-github-keychain` and `git-credentials-plaintext` findings from
[`saw audit`](CLI.md#saw-audit). Those findings deliberately **inform** rather than tell you to delete
something — this page is the reasoning they link to.

## Who this is for

Developers on machines that run `npm install`, VS Code auto-tasks, and AI-agent tooling — the
population that supply-chain worms (Shai-Hulud and variants) target. `saw audit` flags credential
*surfaces* on your dev machine; this page explains what those findings do and don't mean.

## 1. The threat model in one paragraph

The worm runs **as your user** (via an `npm` postinstall, a VS Code folder-open task, an agent auto-run
hook). Once it runs as you, it can read anything *you* can read without extra authentication — your
unlocked login keychain, your `~/.ssh` keys, your `gh` token. Its goal is to grab a working GitHub
credential and **push as you** (to spread and to plant more). So the question is never "is this
credential stored?" — it has to be stored to be usable. The question is **"how much damage can a copy
of it do, and can it even be copied?"**

## 2. Why "cached" is not the same as "exposed"

- A credential must live *somewhere* to work: git-HTTPS → keychain, `gh` → keychain, SSH → `~/.ssh`.
- The macOS login Keychain (and equivalents) is **encrypted at rest** and is the **recommended** store
  — strictly better than plaintext `~/.git-credentials` (`credential.helper store`).
- "The token is in my keychain" is normal, not a misconfiguration.
- The fallacy to avoid: *"it's in use, so it's safe."* Usage and exposure are unrelated. A live token
  is worth stealing **because** it works.

**What actually determines risk** — rank your credentials by these, not by where they're stored:

| Property | Safer | Riskier |
| --- | --- | --- |
| **Lifetime** | short-lived / auto-refreshed (minutes–hours) | non-expiring PAT |
| **Scope** | least-privilege, single-repo | `repo` + `admin:*` + `gist` |
| **Exfiltratability** | hardware-backed `sk-`/FIDO key (cannot be copied) | bearer token or plain key file (copy the bytes, replay anywhere) |

A **bearer token** is the worst of these: copy the string, replay it from the attacker's own machine,
instantly, no key material needed. That's why worms prefer tokens over SSH keys — and why a long-lived,
broadly-scoped bearer token is the finding worth caring about, regardless of *which* keychain slot
holds it.

> `saw audit` does **not** read your token's bytes — it never handles a live secret. So it can't tell a
> short-lived least-scope token from a non-expiring `repo`-scoped PAT. That judgement is yours; this
> table is how to make it.

## 3. The decision: should I act on a cached-credential finding?

First, correct a common bad instinct: **using more than one auth method is fine and normal.** SSH for
some repos, HTTPS + a PAT for others (org SSO, CI, containers/Codespaces, or networks that block SSH
port 22), `gh` for API work — a real dev's machine has several, on purpose, and often because the
environment forces it. The goal is **not** to collapse to one. So the question is not "do I have
another path?" but "do I actually *use* this one?"

```
Do you INTENTIONALLY use HTTPS auth for any project/workflow?
├─ YES → keep it. Do NOT delete it. Instead make THIS credential low-risk:
│        short-lived, least-scope, hardware-backed where the method allows (§2, §4).
├─ NO / it's a stale leftover you don't recognize → removal candidate.
│        Remove it the verified way (§5); you lose nothing because you don't use it.
└─ It's your ONLY path and you're unsure → do NOT delete first. Stand up a
         replacement (§4), verify it works, THEN remove.
```

"Delete it" is only valid for a credential you **don't use**. A path you rely on is not "redundant"
just because another path also exists — deleting it is an outage, not a fix.

## 4. How to stay authenticated (you'll use more than one — harden each)

Authentication needs *a path*, not a *cache*, and most devs keep several paths for different projects
and environments. That's fine — the security goal is that **every** credential you keep is
low-blast-radius (short lifetime, least scope, non-exfiltratable where possible), **not** that you pick
a single method. These are options to combine and harden, not a menu to choose one from —
best-to-workable:

1. **Hardware-backed SSH key** (`sk-ed25519` / FIDO security key) → `git@github.com` remotes.
   - Your session can *sign* with it; a worm **cannot copy** it. This is the only tier that defeats
     copy-and-replay.
   - `ssh-keygen -t ed25519-sk -C "yubikey-github"`, add the `.pub` to GitHub, set your remote to SSH.
2. **`gh` as git's credential helper** — `gh auth setup-git`.
   - git borrows `gh`'s **short-lived, auto-refreshed** keyring token; no separate git cache to rot. A
     stolen copy expires fast. Centrally revocable with `gh auth logout`.
3. **Plain SSH key in `~/.ssh`** (passphrase-protected, loaded into `ssh-agent` for the session).
   - Works and is the common default, but the key file is copyable — protect it with a passphrase so
     the file alone isn't enough.
4. **In-memory HTTPS cache** — `git config --global credential.helper 'cache --timeout=3600'`.
   - Lives in RAM only, evaporates on timeout/reboot; never persisted to disk or keychain.

Check what you use today:

```bash
ssh -T git@github.com                 # "Hi <you>!" => SSH already works
gh auth status                        # is gh logged in, and via keyring?
git remote -v                         # git@github.com => SSH ; https:// => token path
git config --get-all credential.helper
```

## 5. Removing a redundant cached credential — the *verified* way

This is the exact journey that trips people up; do it in order and **verify at the end**.

**a. Find where the helper actually comes from** (it is often NOT in your user config):

```bash
git config --show-origin --get-all credential.helper
```

On macOS this frequently resolves to Apple's Command Line Tools default —
`/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig` — which you **cannot** `--unset`
(it's a read-only system default). `git config --unset credential.helper` will silently succeed and
change nothing.

**b. Reset the inherited helper** by adding an empty value at global scope (an empty helper resets the
list):

```bash
git config --global --add credential.helper ""
git config --get-all credential.helper   # shows: osxkeychain <newline> (blank) => the blank resets it
```

**c. Inspect before deleting** (avoid nuking the wrong entry if you have several):

```bash
security find-internet-password -s github.com -g       # macOS: view first match
# scope by account if needed: -a <account>
```

**d. Delete the cached token:**

```bash
security delete-internet-password -s github.com        # macOS
# Linux (libsecret): git credential-libsecret erase <<< $'protocol=https\nhost=github.com\n'
```

**e. VERIFY it actually stopped caching** — the step everyone skips:

```bash
security find-internet-password -s github.com >/dev/null 2>&1 && echo "STILL PRESENT" || echo "GONE"
printf 'protocol=https\nhost=github.com\n\n' | GIT_TERMINAL_PROMPT=0 git credential fill
#   -> if this prints a `password=` line, a helper is still serving a token; if it errors on
#      "could not read Username", no helper is caching. That error is the success signal.
ssh -T git@github.com                                  # confirm you are STILL authenticated (via SSH)
```

## 6. Scope of the fix — what deletion does NOT touch

There are (at least) three separate github.com credential stores on a typical Mac. Removing one leaves
the others:

| Store | Used by | Removed by §5? |
| --- | --- | --- |
| git-HTTPS token (keychain *internet-password*) | git over HTTPS | ✅ yes |
| `gh` token (keychain *generic-password*, `gh:github.com`) | the `gh` CLI | ❌ no — `gh auth logout` to remove |
| SSH keys (`~/.ssh/id_*`) | git over SSH | ❌ no — removing breaks your pushes |

"Remove the cached credential entirely" ≠ "remove all GitHub credentials from the host." If your goal
is the latter, you also `gh auth logout` and review `~/.ssh` — but note that keeping `gh`'s short-lived
keyring token is a *recommended* end state, not a problem.

## 7. If you actually suspect this host is compromised

This page is steady-state hygiene. If you have real evidence of the worm (see the persistence findings
in `saw audit`), follow the incident-response order instead — **isolate → neutralize persistence →
rebuild → rotate credentials LAST** — because rotating while persistence is live can trigger a reported
home-directory wiper. See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

## 8. Checklist

- [ ] I know how my machine authenticates to GitHub today (SSH / gh-helper / HTTPS token).
- [ ] The credential I'm removing is one I genuinely **don't use** (not merely "I have another path
      too"), or I've stood up a replacement first.
- [ ] My standing tokens are short-lived and least-scope (or I use a hardware-backed key).
- [ ] After removing a cached token, I **verified** caching stopped *and* that I'm still authenticated.
- [ ] I understand `gh` and SSH credentials are separate stores, untouched by deleting the git cache.
