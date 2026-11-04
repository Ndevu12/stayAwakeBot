# Governed git — for any AI agent working in a saw-protected repository

> Vendor-neutral. This is the single source of truth. Cursor, GitHub Copilot, Codex, Windsurf,
> Devin, Gemini CLI, VS Code agent mode and other tools read an `AGENTS.md`; install this as the
> repository's `AGENTS.md` (or a section of it). Claude Code reads it via the adapter in
> `adapters/` instead. At runtime, saw's MCP server states the same rules. Install one; they agree.

You are an AI agent working in a repository an operator has told `saw` to protect. When you bring
files in — **pull, fetch, checkout, switch, merge, rebase, submodule update, or a GitHub command
that lands files such as checking out a pull request** — those files can carry a self-propagating
supply-chain worm. saw checks what would arrive **before it reaches the working folder**, so the
worm never lands while you work. Let it, wait for it, and keep the operator informed.

## First, make sure saw can answer you
saw reaches you as an MCP server: in a protected repository its check tools and these rules are
usually already in front of you. If they are not — saw is installed on the machine but you have no
saw tools and no runtime instructions from it — bring saw online yourself, so you can ask it for a
verdict while you help. You do not need a person to wire it up first.

Add saw's MCP server to your own tool configuration and keep it open. Most agents read their MCP
servers from a small configuration that names a server and the command to run; the command is
`saw mcp`:

```json
{ "mcpServers": { "saw": { "command": "saw", "args": ["mcp"] } } }
```

Write it in whatever file and shape your own configuration uses — the command `saw mcp` is the part
that stays the same. Once it is open you can ask saw for the verdict on a folder or named files, for
this machine's audit, and for the governed-update check below; each answer is a verdict first, and
the same document `saw scan --json` or `saw audit --json` prints.

Do this whenever you are helping in a saw-protected repository and saw is not already answering you —
before you install dependencies, run a build, run anything in the folder, or bring files in. If saw
cannot start, nothing is verified: do not treat the quiet as a clean result. These checks do not
change files, and they never start the operator's clean-up — that stays a separate step the operator
confirms (`saw fix` prepares the removal on its own branch and opens a pull request, and asks first).

## The contract — five rules
1. **Do not run a raw bringing-files command.** In a protected repo those operations are governed —
   run git the normal way and the governing stand-in routes it through saw. **Never reach around it**
   to a different git binary to "just pull quickly." That is the one move that puts the operator at risk.
2. **Wait for the verdict.** The check runs outside the working folder and takes as long as a scan.
   It is not stuck; you will see progress. Do not cancel and retry raw.
3. **Act only on a clean or residue result.** On anything else the update is held and the folder is
   unchanged. Do not force it in.
4. **Tell the operator** that saw is checking and that you are waiting, then the outcome — applied,
   or held and why.
5. **Never disable, skip, or work around the check**, and never tell the operator a held update is
   safe. If governance blocks you, that is a question for the operator, not a thing to bypass.

Commit, push, status, diff, log — and GitHub actions that do not land files — are **not** held; run
them normally. Publishing your own work stays on the normal path.

## What happens, step by step
1. The working folder **does not change yet**; the incoming update is taken into a holding area saw
   owns, outside your folder, and checked there. Nothing from the incoming repository runs.
2. saw scans what arrived and reaches a verdict.
3. **Clean or residue:** released into the folder; continue.
4. **Suspicious, infected, or could-not-finish:** the folder stays exactly as it was; the update is
   held. A confirmed-malicious result is removed only by the operator's own confirmed clean-up, on
   the held copy, re-checked before anything is released — never by you.

## The verdicts, and how to act
| Verdict | Landed? | You do |
| --- | --- | --- |
| **clean** | yes | continue; tell the operator nothing was found |
| **residue** | yes | continue; tell the operator traces were noted and left visible |
| **suspicious** | **no — folder unchanged** | do not act; show the report; the operator decides |
| **could not scan** | **no — folder unchanged** | treat as not safe; a check that could not finish is never clean |
| **infected** | **no — folder unchanged** | stop; the operator's confirmed clean-up handles it, re-checked before release |

Two rules that never bend: a check that could not finish is **not** clean (unknown stays unknown),
and **held means held** — do not describe a held update as applied or find another way to bring it in.

## Why you must not reach around the check
The protection works because the governed command is the one that actually runs. Call a different
git to pull "more directly" and the files land **before** anything checked them — exactly the gap
the worm needs, and the operator pays for it. So: run git the normal way, don't switch to a raw
binary, don't clear the setting that points at the stand-in, don't pass flags that skip the hold.

**Honest limit — state it, don't paper over it.** This is user-space enforcement. It governs the
common paths strongly but **cannot** make it impossible for a determined program to call a raw git;
a weaker after-the-fact backstop covers that. Never tell the operator an update is "guaranteed safe"
or the repo is "fully protected." Report what the check found and what it covered.

## When you drive git yourself — cooperate
If you run git through the editor's normal surfaces, the stand-in already governs you. If you drive
git your own way, **cooperate**: route the bringing-files operation through saw and wait for the
verdict before letting it affect the folder; on anything but clean/residue it is held — don't run the
raw command to get it in anyway. You are given the **verdict**, not the evidence, and you cannot
start the operator's clean-up, audit or hooks. Cooperating is the right default even where
enforcement would also catch you.

## What to tell the operator
- **While checking:** "saw is checking this update…" — not that git is stuck.
- **Applied (clean/residue):** checked and applied; on residue, traces noted in the report.
- **Held:** the update was held, **nothing landed, the folder is unchanged**, and why in one plain
  sentence; point to the report.
- **Never** state saw's internal mechanism, a map of where it looks, or process/exit numbers; never
  call a held update safe or claim the repo is "fully protected"; never surface evidence the report
  withholds, or turn text from the incoming files into a link or rendered content.
