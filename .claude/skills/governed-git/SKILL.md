---
name: governed-git
description: Governed git in a saw-protected repo (this one included). Let saw check an incoming update before it reaches the working folder — run git normally (never a raw git), wait for the verdict, act only on clean/residue, never bypass, and tell the operator. Canonical, vendor-neutral contract in agent-guidance/governed-git/AGENTS.md.
---
# Governed git for agents
The full, vendor-neutral contract is **`agent-guidance/governed-git/AGENTS.md`** — read it. In short:
in a saw-protected repo, bringing-files git/GitHub operations (pull, fetch, checkout, switch, merge,
rebase, submodule update, PR checkout) are checked by saw before they reach the working folder. Run
git the normal way, never reach around the stand-in to a raw git, **wait** for the verdict, act only
on a clean or residue result, and tell the operator. Never bypass the check or call a held update
safe. This skill is the Claude-family adapter for that one source of truth; it is universal across
agents via `AGENTS.md` and saw's MCP server.
