# Security scan — 2026-06-24T09:31:58.172742+00:00

**1 targets** · 1 infected · 29 findings (14 critical, 12 high)

| Target | Source | Status | Findings | Top severity |
|--------|--------|--------|----------|--------------|
| ~/work/stayAwakeBot/stayAwakeBot | local | ❌ INFECTED | 29 | critical |

## Findings

### ~/work/stayAwakeBot/stayAwakeBot
- **[critical]** `loader-fromcharcode-127` — reports/security/latest.json:42
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical]** `loader-seed-var` — reports/security/latest.json:53
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL(\\\\\\\"i…`
- **[critical]** `loader-fromcharcode-127` — reports/security/latest.md:14
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical]** `loader-seed-var` — reports/security/latest.md:17
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL(\\\"inert…`
- **[critical]** `vscode-task-folderopen-exec` — tests/bots/security/fixtures/infected/.vscode/tasks.json
  - VS Code task auto-running a command on folderOpen (executes on open)
  - evidence: `task 'eslint-check' runOn=folderOpen`
- **[critical]** `vscode-task-runs-font` — tests/bots/security/fixtures/infected/.vscode/tasks.json
  - VS Code task whose command executes a font file via node
  - evidence: `node ./public/fonts/fa-solid-400.woff2`
- **[critical]** `loader-fromcharcode-127` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical]** `loader-seed-var` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL("inert");…`
- **[critical]** `fake-font-fa-solid-400` — tests/bots/security/fixtures/infected/public/fonts/fa-solid-400.woff2
  - Payload disguised as FontAwesome fa-solid-400.woff2 (not a real FA file)
- **[critical]** `fake-font-text-woff` — tests/bots/security/fixtures/infected/public/fonts/fa-solid-400.woff2
  - Font file whose bytes are actually JavaScript/text (disguised payload)
  - evidence: `.woff2 without b'wOF2' magic; content is text/JS`
- **[critical]** `loader-fromcharcode-127` — tests/bots/security/test_evasions.py:39
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `* 100 + b"\nString.fromCharCode(127);\n")         self.assertIn("loader-fromchar…`
- **[critical]** `loader-seed-var` — tests/bots/security/test_evasions.py:28
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `(b"/*\x00*/ var _$_1e42 = sfL(0); export default {};")         self.assertIn("lo…`
- **[critical]** `loader-fromcharcode-127` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `d = sfL(0)\nString.fromCharCode(127)\nexport default {a:1};\n"         out = rem…`
- **[critical]** `loader-seed-var` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `     txt = "var _$_abcd = sfL(0)\nString.fromCharCode(127)\nexport default {a:1}…`
- **[high]** `loader-decoder-fn` — reports/security/latest.json:53
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL(\\\\\\\"inert\u2026",           "vector…`
- **[high]** `loader-global-bang` — reports/security/latest.json:207
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high]** `loader-require-hijack` — reports/security/latest.json:218
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `t\\\\\\\"); global[_$_1e42[0]]= require;S\\\\u2026\\\",           \\\"vector\\\"…`
- **[high]** `loader-decoder-fn` — reports/security/latest.md:17
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL(\\\"inert…` - **[critical]** `loader-fr…`
- **[high]** `loader-global-bang` — reports/security/latest.md:58
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high]** `loader-require-hijack` — reports/security/latest.md:61
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `inert\\\"); global[_$_1e42[0]]= require;S\\u2026\",           \"vector\": \"code…`
- **[high]** `vscode-allow-automatic-tasks` — tests/bots/security/fixtures/infected/.vscode/settings.json
  - settings.json enables task.allowAutomaticTasks (required for folderOpen abuse)
  - evidence: `task.allowAutomaticTasks: true`
- **[high]** `loader-decoder-fn` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL("inert"); global[_$_1e42[0]]= require;S…`
- **[high]** `loader-global-bang` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high]** `loader-require-hijack` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `L("inert"); global[_$_1e42[0]]= require;String.fromCharCode(127);               …`
- **[high]** `loader-decoder-fn` — tests/bots/security/test_evasions.py:28
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `r _$_1e42 = sfL(0); export default {};")         self.assertIn("loader-seed-var"…`
- **[high]** `loader-decoder-fn` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `r _$_abcd = sfL(0)\nString.fromCharCode(127)\nexport default {a:1};\n"         o…`
- **[medium]** `gitignore-autopush-markers` — tests/bots/security/fixtures/infected/.gitignore:2
  - Injected .gitignore markers for the worm's auto-push tooling
  - evidence: `ode_modules branch_structure.json temp_auto_push.bat temp_interactive_push.bat `
- **[medium]** `oversized-config-line` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Config file with an abnormally long single line (likely appended payload)
  - evidence: `line 2: 2283 chars`
- **[medium]** `camouflage-blockchain-readme` — tests/bots/security/fixtures/infected/public/fonts/README.md:2
  - Fake 'Blockchain Explorer' fonts README used as camouflage (GlassWorm-family)
  - evidence: `nts for the Blockchain Explorer application. Required: BlockchainFont-Regular, T…`

