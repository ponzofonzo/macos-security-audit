"""End-to-end CLI, scoring, runner, and report tests (no macOS required)."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from macos_security_audit import cli
from macos_security_audit.models import CheckResult, Status
from macos_security_audit.report import build_report, to_html
from macos_security_audit.runner import CommandRunner

from tests.helpers import FIXTURES, NOW


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def replay(name, *extra):
    code, out, _ = run_cli("--replay", os.path.join(FIXTURES, name), "--json", "-", *extra)
    return code, json.loads(out)


class ScoreTests(unittest.TestCase):
    def test_score_excludes_info_skip_error(self):
        results = [CheckResult(str(i), "t", "c", s, "") for i, s in enumerate(
            [Status.PASS, Status.PASS, Status.FAIL, Status.WARN, Status.INFO, Status.SKIP, Status.ERROR])]
        s = cli.score(results)
        self.assertEqual(s["score_percent"], 50)
        self.assertEqual(s["controls_evaluated"], 4)
        self.assertEqual(s["not_evaluated"], ["5", "6"])

    def test_no_controls(self):
        self.assertIsNone(cli.score([])["score_percent"])


class FixtureTests(unittest.TestCase):
    def test_hardened(self):
        code, rep = replay("hardened.json", "--fail-on", "warn")
        self.assertEqual(code, 0)
        self.assertEqual(rep["summary"]["score_percent"], 100)
        self.assertEqual(rep["summary"]["overall_status"], Status.PASS)

    def test_at_risk(self):
        code, rep = replay("at-risk.json", "--fail-on", "fail")
        self.assertEqual(code, 1)
        failed = set(rep["summary"]["failed_controls"])
        self.assertTrue({"filevault", "gatekeeper", "firewall", "guest_account", "auto_login",
                         "security_updates"} <= failed)
        self.assertIn("remote_login", rep["summary"]["not_evaluated"])
        self.assertNotIn("user1", json.dumps(rep))

    def test_html_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.html")
            code, _, _ = run_cli("--replay", os.path.join(FIXTURES, "at-risk.json"), "--html", path, "--quiet")
            self.assertEqual(code, 0)
            with open(path, encoding="utf-8") as fh:
                page = fh.read()
            self.assertIn("Security score:", page)
            self.assertIn("Synthetic data", page)


class CliTests(unittest.TestCase):
    def test_refuses_live_run_off_macos(self):
        with mock.patch.object(cli.sys, "platform", "linux"):
            code, _, err = run_cli()
        self.assertEqual(code, 3)
        self.assertIn("macOS only", err)

    def test_unknown_check(self):
        self.assertEqual(run_cli("--check", "bogus")[0], 3)

    def test_list(self):
        code, out, _ = run_cli("--list-checks")
        self.assertEqual(code, 0)
        self.assertIn("filevault", out)

    def test_read_only_commands_only(self):
        """Guard: no mutating flags are ever passed to security tools."""
        calls = []
        real_run = CommandRunner.run

        def spy(self, args, timeout=None):
            calls.append(list(args))
            return real_run(self, ["/nonexistent/stub"], timeout)

        with mock.patch.object(cli.sys, "platform", "darwin"), mock.patch.object(CommandRunner, "run", spy):
            run_cli("--quiet")
        self.assertEqual(len(calls), 15)
        flat = " ".join(" ".join(c) for c in calls)
        for forbidden in ("enable", "disable", "--set", "-setremotelogin", "-screenLock on", "-screenLock off",
                          "binary1", "write", "-create", "-delete", "-append"):
            self.assertNotIn(forbidden, flat)


class RunnerReportTests(unittest.TestCase):
    def test_runner_never_raises(self):
        self.assertTrue(CommandRunner().run(["/nonexistent/x"]).not_found)
        self.assertTrue(CommandRunner().run([sys.executable, "-c", "pass"]).ok)

    def test_html_escaping(self):
        rep = build_report([CheckResult("x", "X", "C", Status.FAIL, "<script>x</script>")], tool="t",
                           version="1", generated_at=NOW, data_source="live")
        self.assertNotIn("<script>x", to_html(rep, "T"))


if __name__ == "__main__":
    unittest.main()
