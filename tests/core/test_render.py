#!/usr/bin/env python3
"""Unit tests for the shared terminal-render toolkit (core.render): colour gating, the palette,
width-aware wrapping, rules, and terminal-width fallback. These are the MECHANISM both the scan
sink and the audit report compose, so they are pinned here once."""
from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import render


class TestPaint(unittest.TestCase):
    def test_on_wraps_code_and_resets(self):
        self.assertEqual(render.paint("x", "\033[31m", on=True), "\033[31mx\033[0m")

    def test_off_is_identity_even_with_a_code(self):
        self.assertEqual(render.paint("x", "\033[31m", on=False), "x")

    def test_on_without_a_code_is_identity(self):
        # A palette miss (code=None) must never emit a bare RESET or raise.
        self.assertEqual(render.paint("x", None, on=True), "x")

    def test_no_reset_leaks_when_off(self):
        self.assertNotIn("\033", render.paint("x", "\033[31m", on=False))


class TestPathLink(unittest.TestCase):
    def test_off_is_plain_path(self):
        from pathlib import Path
        p = Path("/tmp/report/latest.md")
        self.assertEqual(render.path_link(p, on=False), str(p))
        self.assertNotIn("\033", render.path_link(p, on=False))

    def test_on_is_coloured_and_hyperlinked(self):
        from pathlib import Path
        p = Path("/tmp/report/latest.md")
        out = render.path_link(p, on=True)
        self.assertIn(str(p), out)                          # visible text is still the path
        self.assertIn("\033]8;;file://", out)               # OSC 8 hyperlink
        self.assertIn(render.LINK, out)                     # bold-cyan colour
        self.assertIn(render.RESET, out)
        self.assertTrue(out.endswith("\033]8;;\033\\"))     # link closer

    def test_untrusted_path_cannot_inject_terminal_escapes(self):
        # #1294: a path embedding a nested OSC-8 escape + a bidi override must not hijack the terminal
        # or a CI log. The visible text is sanitized; the click target is still built from the raw path.
        from pathlib import Path
        evil = Path("/tmp/\033]8;;http://evil\033\\click‮dm.md")
        off = render.path_link(evil, on=False)
        self.assertNotIn("\033", off)                       # every control/escape char neutralized
        self.assertNotIn("‮", off)                     # bidi override neutralized
        on = render.path_link(evil, on=True)
        self.assertNotIn("\033]8;;http://evil", on)         # the injected OSC-8 opener did NOT survive
        self.assertNotIn("‮", on)
        self.assertIn("\033]8;;file://", on)                # our own hyperlink wrapper is intact
        self.assertTrue(on.endswith("\033]8;;\033\\"))


class TestRule(unittest.TestCase):
    def test_width(self):
        self.assertEqual(render.rule(5), "─────")

    def test_zero_and_negative_are_empty(self):
        self.assertEqual(render.rule(0), "")
        self.assertEqual(render.rule(-4), "")

    def test_custom_char(self):
        self.assertEqual(render.rule(3, "="), "===")


class TestWrap(unittest.TestCase):
    def test_short_text_one_line_with_indent(self):
        self.assertEqual(render.wrap("hello world", 40, indent=2), ["  hello world"])

    def test_wraps_to_width(self):
        lines = render.wrap("one two three four five six", 12)
        self.assertTrue(all(len(l) <= 12 for l in lines))
        self.assertGreater(len(lines), 1)
        self.assertEqual(" ".join(lines).split(), "one two three four five six".split())

    def test_hanging_indent_on_continuations(self):
        lines = render.wrap("alpha beta gamma delta", 16, indent=0, hanging=4)
        self.assertFalse(lines[0].startswith(" "))          # first line flush
        self.assertTrue(lines[1].startswith("    "))         # continuations hang 4

    def test_long_unbreakable_token_is_not_split(self):
        # A path/URL longer than width must survive intact (a mangled path is worse than a long line).
        url = "https://example.com/a/very/long/unbreakable/path/segment/token"
        lines = render.wrap(f"see {url} now", 20)
        self.assertIn(url, "\n".join(lines))                 # token never chopped
        self.assertTrue(any(url in l for l in lines))

    def test_empty_text_yields_no_lines(self):
        self.assertEqual(render.wrap("", 40), [])

    def test_tiny_width_does_not_raise(self):
        self.assertEqual(render.wrap("hi there", 1, indent=3), ["   hi there"])


class TestTermWidth(unittest.TestCase):
    def test_uses_reported_columns(self):
        with mock.patch.object(render.shutil, "get_terminal_size",
                               return_value=mock.Mock(columns=123)):
            self.assertEqual(render.term_width(), 123)

    def test_falls_back_on_exception(self):
        with mock.patch.object(render.shutil, "get_terminal_size", side_effect=OSError):
            self.assertEqual(render.term_width(default=77), 77)

    def test_falls_back_on_nonpositive(self):
        with mock.patch.object(render.shutil, "get_terminal_size",
                               return_value=mock.Mock(columns=0)):
            self.assertEqual(render.term_width(default=80), 80)


class TestBlock(unittest.TestCase):
    def test_plain_paragraph_indented(self):
        self.assertEqual(render.block("hello world", indent=2, width=40), ["  hello world"])

    def test_marker_on_first_line_text_hangs_under_it(self):
        # First line: indent + marker + text; continuations align under the TEXT (indent+len(marker)).
        out = render.block("alpha beta gamma delta epsilon", indent=2, width=20, marker="→ ")
        self.assertTrue(out[0].startswith("  → alpha"))
        self.assertTrue(out[1].startswith("    "))          # 2 indent + 2 marker = 4-space hang
        self.assertFalse(out[1].startswith("     "))

    def test_marker_coloured_only_when_on(self):
        on = render.block("x", marker="• ", code="\033[31m", color=True)
        off = render.block("x", marker="• ", code="\033[31m", color=False)
        self.assertIn("\033[31m", on[0])
        self.assertNotIn("\033[", off[0])
        self.assertEqual(off, ["• x"])

    def test_empty_text_yields_no_lines(self):
        self.assertEqual(render.block("", indent=4, marker="• "), [])


class TestMarkedList(unittest.TestCase):
    def test_bulleted(self):
        out = render.marked_list(["one", "two"], indent=2, width=40)
        self.assertEqual(out, ["  • one", "  • two"])

    def test_numbered(self):
        out = render.marked_list(["a", "b", "c"], ordered=True, indent=0, width=40)
        self.assertEqual(out, ["1. a", "2. b", "3. c"])

    def test_numbers_right_align_past_nine(self):
        out = render.marked_list([f"i{n}" for n in range(1, 11)], ordered=True, width=40)
        self.assertTrue(out[0].startswith(" 1. "))          # padded to width of "10"
        self.assertTrue(out[9].startswith("10. "))

    def test_start_offset(self):
        self.assertEqual(render.marked_list(["x"], ordered=True, start=3), ["3. x"])

    def test_wraps_each_item_with_hanging_indent(self):
        out = render.marked_list(["short", "a much longer item that will certainly wrap here"],
                                 ordered=True, indent=0, width=24)
        self.assertEqual(out[0], "1. short")
        self.assertTrue(out[2].startswith("   "))           # continuation hangs under the text (3)

    def test_empty_list_is_empty(self):
        self.assertEqual(render.marked_list([], ordered=True), [])


class TestPalette(unittest.TestCase):
    def test_severity_has_every_level_both_surfaces_grade(self):
        for k in ("critical", "high", "medium", "low", "warning", "info", "ok"):
            self.assertIn(k, render.SEVERITY)
            self.assertTrue(render.SEVERITY[k].startswith("\033["))

    def test_status_covers_the_scan_verdicts(self):
        for k in ("INFECTED", "SUSPECT", "ERROR", "clean"):
            self.assertIn(k, render.STATUS)
            self.assertTrue(render.STATUS[k].startswith("\033["))


if __name__ == "__main__":
    unittest.main()


class TestMarkerVocabulary(unittest.TestCase):
    """The glyph vocabulary (`render.MARKER`) is the counterpart to the colour one, and it lives
    beside it for the same reason: the audit report, the scan report and the CLI status lines each
    used to choose their own markers, so "what does a tick mean?" could drift the way "what colour
    is critical?" no longer can."""

    def _severities_emitted_by_hygiene(self) -> set[str]:
        """Derive the inventory FROM THE SOURCE, never a hardcoded list — a new severity added to a
        probe must fail this suite rather than silently render as an unpainted info bullet."""
        pkg = Path(render.__file__).resolve().parents[1] / "bots" / "security" / "hygiene"
        found: set[str] = set()
        for py in pkg.rglob("*.py"):
            found |= set(re.findall(r'severity=["\']([a-z]+)["\']', py.read_text()))
        self.assertTrue(found, "found no severities — the scrape broke, so this test proves nothing")
        return found

    def test_every_emitted_severity_has_both_a_colour_and_a_marker(self):
        # The defect this pins: `unknown` (#1332's "surface could not be verified") existed in
        # NEITHER map, so it fell through to the info bullet AND rendered unpainted — the one state
        # meaning "we could not establish this" was pixel-identical to a review-worthy nudge.
        for sev in sorted(self._severities_emitted_by_hygiene()):
            self.assertIn(sev, render.SEVERITY, f"severity {sev!r} has no colour")
            self.assertIn(sev, render.MARKER, f"severity {sev!r} has no marker")

    def test_unknown_is_distinguishable_from_info(self):
        # Not-established must not read as a nudge, in EITHER channel — glyph or colour.
        self.assertNotEqual(render.MARKER["unknown"], render.MARKER["info"])
        self.assertNotEqual(render.SEVERITY["unknown"], render.SEVERITY["info"])

    def test_ok_is_reserved_for_an_established_positive(self):
        # `ok`/✓ asserts a check ESTABLISHED a positive. A scoped negative ("none found here") is
        # `info`, and a check that could not run is `unknown` — neither may share the tick.
        self.assertNotEqual(render.MARKER["ok"], render.MARKER["info"])
        self.assertNotEqual(render.MARKER["ok"], render.MARKER["unknown"])

    def test_no_marker_is_a_double_width_emoji(self):
        # `block()`/`marked_list()` hang continuations by len(marker) — a COUNT OF CODE POINTS, not
        # display columns. An emoji (variation selector U+FE0F) renders double-width, so it silently
        # shifts every continuation line and misaligns rows against their single-width neighbours.
        for name, glyph in render.MARKER.items():
            self.assertNotIn("️", glyph, f"MARKER[{name!r}] is an emoji presentation")
            self.assertEqual(len(glyph), 1, f"MARKER[{name!r}] must be one code point")

    def test_block_hanging_indent_holds_for_every_marker(self):
        # The mechanical consequence of the rule above, asserted rather than assumed.
        for name, glyph in render.MARKER.items():
            marker = f"{glyph} "
            lines = render.block("word " * 40, indent=2, width=40, marker=marker)
            self.assertGreater(len(lines), 1, f"{name}: needed a wrapped sample")
            hang = 2 + len(marker)
            for cont in lines[1:]:
                self.assertTrue(cont.startswith(" " * hang),
                                f"MARKER[{name!r}] broke the hanging indent")
                self.assertNotEqual(cont[hang], " ", f"MARKER[{name!r}] over-indented")


class TestVocabularyIsActuallyAdopted(unittest.TestCase):
    """Defining the vocabulary is not the point — ADOPTING it is. A `MARKER` map that no caller
    reads leaves the glyphs exactly as scattered as before, which is the drift it exists to stop.

    So: no report surface may hardcode a marker glyph in a string literal. Parsed with `ast` so
    comments and docstrings (which legitimately discuss the glyphs) are not mistaken for output.
    """

    EMOJI_VS = "️"   # variation selector — the emoji presentation form

    def _surfaces(self) -> list[Path]:
        sec = Path(render.__file__).resolve().parents[1] / "bots" / "security"
        files = sorted((sec / "hygiene").rglob("*.py")) + sorted((sec / "sinks").rglob("*.py"))
        self.assertTrue(files, "found no render surfaces — the scan broke, so this proves nothing")
        return files

    def test_no_surface_hardcodes_a_glyph_in_MARKER_POSITION(self):
        # Scoped to marker POSITION — a literal that begins a rendered line — rather than to the
        # glyph anywhere. `→` and `·` are also ordinary punctuation ("isolate → rebuild", "a · b"),
        # and flagging those would make this test noise that gets deleted rather than a rule that
        # holds. What must not drift is the glyph that LEADS a line, because that is the one the
        # reader decodes as severity.
        import ast
        offenders: list[str] = []
        for path in self._surfaces():
            for node in ast.walk(ast.parse(path.read_text())):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                lead = node.value.lstrip()
                for name, glyph in render.MARKER.items():
                    if not lead.startswith(glyph):
                        continue
                    # Documented exception: a standalone incident BANNER may use the emoji
                    # presentation. It never sits in an aligned list, so the width rule that bars
                    # emoji from the vocabulary does not apply there.
                    if lead.startswith(glyph + self.EMOJI_VS):
                        continue
                    offenders.append(f"{path.name}:{node.lineno} leads with MARKER[{name!r}]")
        self.assertEqual(offenders, [], "use MARKER[...] instead of a literal glyph:\n  " +
                         "\n  ".join(offenders))
