# Security scan — 2026-06-26T23:57:37.806856+00:00

**1 targets** · 1 infected · 0 suspicious · 36 findings (18 critical, 14 high)

_Verdict: **infected** = a confirmed (high-confidence) signature matched; **suspicious** = only heuristic match(es) that benign code can also produce — review, not asserted as malware._

| Target | Source | Status | Findings | Top severity |
|--------|--------|--------|----------|--------------|
| ~/work/stayAwakeBot/stayAwakeBot | local | ❌ INFECTED | 36 | critical |

## Findings

### ~/work/stayAwakeBot/stayAwakeBot
- **[critical · confirmed]** `loader-fromcharcode-127` — reports/security/latest.json:50
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical · confirmed]** `loader-seed-var` — reports/security/latest.json:62
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL(\\\\\\\\\…`
- **[critical · confirmed]** `loader-fromcharcode-127` — reports/security/latest.md:16
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical · confirmed]** `loader-seed-var` — reports/security/latest.md:19
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL(\\\\\\\\\…`
- **[critical · confirmed]** `vscode-task-folderopen-exec` — tests/bots/security/fixtures/infected/.vscode/tasks.json
  - VS Code task auto-running a command on folderOpen (executes on open)
  - evidence: `task 'eslint-check' runOn=folderOpen`
- **[critical · confirmed]** `vscode-task-runs-font` — tests/bots/security/fixtures/infected/.vscode/tasks.json
  - VS Code task whose command executes a font file via node
  - evidence: `node ./public/fonts/fa-solid-400.woff2`
- **[critical · confirmed]** `loader-fromcharcode-127` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `]]= require;String.fromCharCode(127);                                           …`
- **[critical · confirmed]** `loader-seed-var` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; var x =sfL("inert");…`
- **[critical · confirmed]** `fake-font-fa-solid-400` — tests/bots/security/fixtures/infected/public/fonts/fa-solid-400.woff2
  - Payload disguised as FontAwesome fa-solid-400.woff2 (not a real FA file)
- **[critical · confirmed]** `fake-font-text-woff` — tests/bots/security/fixtures/infected/public/fonts/fa-solid-400.woff2
  - Font file whose bytes are actually JavaScript/text (disguised payload)
  - evidence: `.woff2 without b'wOF2' magic; content is text/JS`
- **[critical · confirmed]** `loader-fromcharcode-127` — tests/bots/security/test_evasions.py:39
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `* 100 + b"\nString.fromCharCode(127);\n")         self.assertIn("loader-fromchar…`
- **[critical · confirmed]** `loader-seed-var` — tests/bots/security/test_evasions.py:28
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `(b"/*\x00*/ var _$_1e42 = sfL(0); export default {};")         self.assertIn("lo…`
- **[critical · confirmed]** `loader-fromcharcode-127` — tests/bots/security/test_obfuscation_file.py:231
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: ` * 40) + "];String.fromCharCode(127)"         for path in ("lib/app.min.js", ".p…`
- **[critical · confirmed]** `loader-seed-var` — tests/bots/security/test_obfuscation_file.py:47
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `om 'react'\nvar _$_1e42='seed';\n" + packed         self.assertIn(OBF, _scan({"C…`
- **[critical · confirmed]** `loader-fromcharcode-127` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `d = sfL(0)\nString.fromCharCode(127)\nexport default {a:1};\n"         out = rem…`
- **[critical · confirmed]** `loader-seed-var` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `     txt = "var _$_abcd = sfL(0)\nString.fromCharCode(127)\nexport default {a:1}…`
- **[critical · confirmed]** `loader-fromcharcode-127` — tests/bots/security/test_verdict.py:102
  - Obfuscated loader fingerprint — fromCharCode(127) string shuffler
  - evidence: `2 = sfL(0); String.fromCharCode(127);\n"})         self.assertEqual(r.verdict, I…`
- **[critical · confirmed]** `loader-seed-var` — tests/bots/security/test_verdict.py:102
  - Obfuscated loader seed variable (var/let/const _$_xxxx=)
  - evidence: `({"x.mjs": "var _$_1e42 = sfL(0); String.fromCharCode(127);\n"})         self.as…`
- **[high · confirmed]** `loader-decoder-fn` — reports/security/latest.json:62
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL(\\\\\\\\\\\\\\\\\\\u2026",           "v…`
- **[high · confirmed]** `loader-global-bang` — reports/security/latest.json:278
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high · confirmed]** `loader-require-hijack` — reports/security/latest.json:290
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `\\\\\\\\"); global[_$_1e42[0]]= require;S\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\…`
- **[high · confirmed]** `loader-decoder-fn` — reports/security/latest.md:19
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL(\\\\\\\\\…` - **[critical · confirmed]*…`
- **[high · confirmed]** `loader-global-bang` — reports/security/latest.md:72
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high · confirmed]** `loader-require-hijack` — reports/security/latest.md:75
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `\\\\\\\\"); global[_$_1e42[0]]= require;S\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\…`
- **[high · confirmed]** `vscode-allow-automatic-tasks` — tests/bots/security/fixtures/infected/.vscode/settings.json
  - settings.json enables task.allowAutomaticTasks (required for folderOpen abuse)
  - evidence: `task.allowAutomaticTasks: true`
- **[high · confirmed]** `loader-decoder-fn` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `t';function sfL(w){return w}; var x =sfL("inert"); global[_$_1e42[0]]= require;S…`
- **[high · confirmed]** `loader-global-bang` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Loader bootstrap assigning global['!']
  - evidence: `ault config;global['!']='inert';var _$_1e42= 'inert';function sfL(w){return w}; …`
- **[high · confirmed]** `loader-require-hijack` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Loader reassigning global.require to smuggle CommonJS into ESM
  - evidence: `L("inert"); global[_$_1e42[0]]= require;String.fromCharCode(127);               …`
- **[high · confirmed]** `loader-decoder-fn` — tests/bots/security/test_evasions.py:28
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `r _$_1e42 = sfL(0); export default {};")         self.assertIn("loader-seed-var"…`
- **[high · confirmed]** `loader-decoder-fn` — tests/bots/security/test_obfuscation_file.py:63
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `x';function sfL(w){return w}"         self.assertLess(max(len(l) for l in line.s…`
- **[high · confirmed]** `loader-decoder-fn` — tests/bots/security/test_remediation.py:84
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `r _$_abcd = sfL(0)\nString.fromCharCode(127)\nexport default {a:1};\n"         o…`
- **[high · confirmed]** `loader-decoder-fn` — tests/bots/security/test_verdict.py:102
  - Obfuscated loader decoder call — the sfL decoder function
  - evidence: `r _$_1e42 = sfL(0); String.fromCharCode(127);\n"})         self.assertEqual(r.ve…`
- **[medium · confirmed]** `gitignore-autopush-markers` — tests/bots/security/fixtures/infected/.gitignore:2
  - Injected .gitignore markers for the worm's auto-push tooling
  - evidence: `ode_modules branch_structure.json temp_auto_push.bat temp_interactive_push.bat `
- **[medium · heuristic]** `oversized-config-line` — tests/bots/security/fixtures/infected/postcss.config.mjs:2
  - Config file with an abnormally long single line (likely appended payload)
  - evidence: `line 2: 2283 chars; loader fingerprint: loader-fromcharcode-127`
- **[medium · heuristic]** `obfuscated-source-file` — tests/bots/security/fixtures/infected/postcss.config.mjs
  - Hand-authored source/config file containing packed/obfuscated payload (line-agnostic)
  - evidence: `loader fingerprint on raw content: loader-fromcharcode-127`
- **[medium · confirmed]** `camouflage-blockchain-readme` — tests/bots/security/fixtures/infected/public/fonts/README.md:2
  - Fake 'Blockchain Explorer' fonts README used as camouflage (GlassWorm-family)
  - evidence: `nts for the Blockchain Explorer application. Required: BlockchainFont-Regular, T…`

