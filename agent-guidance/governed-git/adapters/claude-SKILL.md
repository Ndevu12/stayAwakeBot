---
name: governed-git
description: Governed git in a saw-protected repo. Let saw check an incoming update before it reaches the working folder — run git normally (never a raw git), wait for the verdict, act only on clean/residue, never bypass, and tell the operator. Full contract in AGENTS.md.
---
# Governed git for agents (Claude adapter)
Claude Code does not read `AGENTS.md`, so this skill carries the pointer. **Read and follow
`AGENTS.md` (governed git)** in this repository — the five rules, the verdicts, why not to bypass,
the cooperative path, and what to tell the operator. The canonical, vendor-neutral source is that
`AGENTS.md`; this adapter exists only so a Claude-family agent loads it.
