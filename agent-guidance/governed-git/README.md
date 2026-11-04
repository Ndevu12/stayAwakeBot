# governed-git — universal agent guidance

Teaches **any** AI agent working in a saw-protected repository to let saw check an incoming git or
GitHub update before it reaches the working folder. One source of truth, installed in whatever form
a given agent reads.

- **`AGENTS.md`** — the canonical, vendor-neutral contract. Install it as the repository's
  `AGENTS.md` (or merge it in). Read natively by Cursor, GitHub Copilot, Codex, Windsurf, Devin,
  Gemini CLI, VS Code agent mode, Zed and other AGENTS.md-aware tools.
- **`adapters/`** — thin pointers for tools that do not read `AGENTS.md`:
  - `claude-SKILL.md` → install at `.claude/skills/governed-git/SKILL.md` (Claude Code; it does not
    read AGENTS.md). A `CLAUDE.md` line referencing `AGENTS.md` works too.
  - `cursor.mdc` → `.cursor/rules/governed-git.mdc` (optional; Cursor also reads `AGENTS.md`).
  - `copilot-instructions.md` → append to `.github/copilot-instructions.md` (optional; Copilot also
    reads `AGENTS.md`).
- **Runtime:** saw's MCP server states the same rules to any MCP-capable agent, so an agent is
  instructed even without a file in the repo. The file and the MCP instructions are kept in agreement.

Install the adapter that matches the operator's agent (the editor extension can do this per detected
tool); every form points back to the one `AGENTS.md`.
