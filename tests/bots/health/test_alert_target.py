#!/usr/bin/env python3
"""Where the health sentinel files its status issue, and the CLI's call into the service.

Two regressions are pinned here. (1) `stayawake-health-check` passed a third argument to
`service.run_check`, which takes two — every scheduled run died with a TypeError before reaching a
check, and nothing covered the call. (2) The status issue used to be filed into whatever repository
was running the check, taken from the ambient environment. An uptime alert names the endpoints it
monitors and carries their outage history, so the destination is now an explicit operator choice or
there is none.
"""
from __future__ import annotations

import inspect
import unittest
from unittest import mock

from stayawake.bots.health import alerter, service
from stayawake.bots.health.cli import check as check_cli


class CliCallsServiceCorrectly(unittest.TestCase):
    def test_cli_passes_exactly_what_run_check_accepts(self):
        """The CLI's call must be satisfiable by the service signature."""
        sig = inspect.signature(service.run_check)
        with mock.patch.object(service, "run_check", return_value=0) as run:
            with mock.patch("sys.argv", ["stayawake-health-check", "--config", "cfg.yml"]):
                with self.assertRaises(SystemExit) as exit_ctx:
                    check_cli.main()
        self.assertEqual(exit_ctx.exception.code, 0)
        run.assert_called_once()
        # The recorded call must bind against the real signature — this is what failed in prod.
        sig.bind(*run.call_args.args, **run.call_args.kwargs)

    def test_fail_on_unhealthy_is_forwarded(self):
        with mock.patch.object(service, "run_check", return_value=1) as run:
            with mock.patch("sys.argv", ["stayawake-health-check", "--fail-on-unhealthy"]):
                with self.assertRaises(SystemExit) as exit_ctx:
                    check_cli.main()
        self.assertEqual(exit_ctx.exception.code, 1)
        self.assertIn(True, run.call_args.args)


class AlertTargetIsExplicit(unittest.TestCase):
    def test_unset_means_no_issue_is_filed(self):
        self.assertIsNone(alerter._alert_target({}))

    def test_explicit_owner_name_is_used(self):
        self.assertEqual(alerter._alert_target({"alert_repo": "acme/ops"}), ("acme", "ops"))

    def test_malformed_target_is_refused_rather_than_guessed(self):
        for bad in ["ops", "acme/", "/ops", ""]:
            with self.subTest(bad=bad):
                self.assertIsNone(alerter._alert_target({"alert_repo": bad}))

    def test_ambient_repository_is_never_the_destination(self):
        """Even with a token and GITHUB_REPOSITORY set, no issue is written without alert_repo."""
        with mock.patch.object(alerter.env, "github_token", return_value="t"), \
             mock.patch.object(alerter.env, "github_slug", return_value=("someone", "public-repo")), \
             mock.patch.object(alerter.issue_state, "save") as save, \
             mock.patch.object(alerter.issue_state, "load", return_value=(None, None)):
            alerter.publish([{"name": "A", "url": "https://a", "healthy": False,
                              "reason": "timeout", "status_code": None, "response_ms": 0}], {})
        save.assert_not_called()


class CheckAlwaysRuns(unittest.TestCase):
    """The check must happen regardless of the exit-code flag.

    `run_check` once read `fail_on_unhealthy and asyncio.run(_check_async(...))`, and `and`
    short-circuits: with the flag off the check was never invoked, so the process reported success
    having contacted nothing. A monitor that is green without looking is worse than one that fails.
    """

    def _run(self, *, fail_on_unhealthy, unhealthy):
        # A plain callable, not an AsyncMock: asyncio.run is stubbed too, so a real coroutine
        # would be created and never awaited, emitting a warning that could mask a real one.
        with mock.patch.object(service, "_check_async", new=lambda path: "coro"):
            with mock.patch.object(service.asyncio, "run", side_effect=lambda c: unhealthy) as run:
                code = service.run_check("cfg.yml", fail_on_unhealthy)
        return code, run.call_count

    def test_check_runs_when_the_flag_is_off(self):
        code, calls = self._run(fail_on_unhealthy=False, unhealthy=True)
        self.assertEqual(calls, 1, "the check must run even when it cannot change the exit code")
        self.assertEqual(code, 0, "without the flag an unhealthy endpoint is reported, not failed")

    def test_check_runs_when_the_flag_is_on(self):
        code, calls = self._run(fail_on_unhealthy=True, unhealthy=True)
        self.assertEqual(calls, 1)
        self.assertEqual(code, 1, "with the flag an unhealthy endpoint sets a non-zero exit")

    def test_healthy_is_zero_either_way(self):
        for flag in (True, False):
            with self.subTest(fail_on_unhealthy=flag):
                code, calls = self._run(fail_on_unhealthy=flag, unhealthy=False)
                self.assertEqual(calls, 1)
                self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
