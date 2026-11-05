"""Unit tests for security checks using synthetic command output (no macOS required)."""

import json
import unittest

from macos_security_audit.checks import Context, Options, run_checks
from macos_security_audit.models import Status

from tests.helpers import (LW_LOCAL, LW_MANAGED, NOW, SU_LOCAL, SU_MANAGED, XPROTECT, fake_runner, plist,
                           run_one)

FW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class FileVaultTests(unittest.TestCase):
    CMD = "/usr/bin/fdesetup status"

    def test_states(self):
        self.assertEqual(run_one("filevault", {self.CMD: (0, "FileVault is On.\n")}).status, Status.PASS)
        self.assertEqual(run_one("filevault", {self.CMD: (0, "FileVault is Off.\n")}).status, Status.FAIL)
        r = run_one("filevault", {self.CMD: (0, "FileVault is On.\nEncryption in progress: Percent completed = 37.5\n")})
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("37.5", r.summary)
        r = run_one("filevault", {self.CMD: (0, "FileVault is On.\nDecryption in progress: Percent completed = 5\n")})
        self.assertEqual(r.status, Status.FAIL)

    def test_failures(self):
        self.assertEqual(run_one("filevault", {}).status, Status.SKIP)
        self.assertEqual(run_one("filevault", {self.CMD: (0, "???")}).status, Status.ERROR)
        self.assertEqual(run_one("filevault", {self.CMD: (1, "", "Error: boom")}).status, Status.ERROR)


class SipTests(unittest.TestCase):
    CMD = "/usr/bin/csrutil status"

    def test_enabled_disabled(self):
        self.assertEqual(run_one("sip", {self.CMD: (0, "System Integrity Protection status: enabled.\n")}).status,
                         Status.PASS)
        self.assertEqual(run_one("sip", {self.CMD: (0, "System Integrity Protection status: disabled.\n")}).status,
                         Status.FAIL)

    def test_custom_lists_disabled_components(self):
        out = ("System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n"
               "\tKext Signing: disabled\n\tFilesystem Protections: enabled\n")
        r = run_one("sip", {self.CMD: (0, out)})
        self.assertEqual(r.status, Status.WARN)
        self.assertEqual(r.details["disabled_components"], ["Kext Signing"])


class GatekeeperTests(unittest.TestCase):
    CMD = "/usr/sbin/spctl --status"

    def test_states(self):
        self.assertEqual(run_one("gatekeeper", {self.CMD: (0, "assessments enabled\n")}).status, Status.PASS)
        self.assertEqual(run_one("gatekeeper", {self.CMD: (1, "assessments disabled\n")}).status, Status.FAIL)

    def test_failure(self):
        self.assertEqual(run_one("gatekeeper", {self.CMD: (1, "", "spctl: weird\n")}).status, Status.ERROR)
        self.assertEqual(run_one("gatekeeper", {}).status, Status.SKIP)


class FirewallTests(unittest.TestCase):
    def test_global_state(self):
        cmd = FW + " --getglobalstate"
        self.assertEqual(run_one("firewall", {cmd: (0, "Firewall is enabled. (State = 1)\n")}).status, Status.PASS)
        r = run_one("firewall", {cmd: (0, "Firewall is blocking all non-essential incoming connections. (State = 2)\n")})
        self.assertEqual(r.status, Status.PASS)
        self.assertIn("blocking all", r.summary)
        self.assertEqual(run_one("firewall", {cmd: (0, "Firewall is disabled. (State = 0)\n")}).status, Status.FAIL)
        self.assertEqual(run_one("firewall", {cmd: (0, "Firewall is enabled.\n")}).status, Status.PASS)
        self.assertEqual(run_one("firewall", {cmd: (0, "hmm\n")}).status, Status.ERROR)

    def test_stealth_both_wordings(self):
        cmd = FW + " --getstealthmode"
        self.assertEqual(run_one("firewall_stealth", {cmd: (0, "Firewall stealth mode is on\n")}).status, Status.PASS)
        self.assertEqual(run_one("firewall_stealth", {cmd: (0, "Stealth mode enabled\n")}).status, Status.PASS)
        self.assertEqual(run_one("firewall_stealth", {cmd: (0, "Firewall stealth mode is off\n")}).status, Status.WARN)
        self.assertEqual(run_one("firewall_stealth", {cmd: (0, "Stealth mode disabled\n")}).status, Status.WARN)


class RemoteLoginTests(unittest.TestCase):
    CMD = "/usr/sbin/systemsetup -getremotelogin"

    def test_states(self):
        self.assertEqual(run_one("remote_login", {self.CMD: (0, "Remote Login: Off\n")}).status, Status.PASS)
        self.assertEqual(run_one("remote_login", {self.CMD: (0, "Remote Login: On\n")}).status, Status.WARN)

    def test_without_admin_is_skip(self):
        r = run_one("remote_login", {self.CMD: (1, "You need administrator access to run this tool... exiting!\n")})
        self.assertEqual(r.status, Status.SKIP)


class ScreenLockTests(unittest.TestCase):
    CMD = "/usr/sbin/sysadminctl -screenLock status"

    def stderr(self, msg):
        return {self.CMD: (0, "", "2026-01-15 12:00:00.000 sysadminctl[1:2] {}\n".format(msg))}

    def test_states(self):
        self.assertEqual(run_one("screen_lock", self.stderr("screenLock delay is immediate")).status, Status.PASS)
        self.assertEqual(run_one("screen_lock", self.stderr("screenLock delay is 5 seconds")).status, Status.PASS)
        r = run_one("screen_lock", self.stderr("screenLock delay is 300 seconds"))
        self.assertEqual(r.status, Status.WARN)
        self.assertEqual(r.details["delay_seconds"], 300)
        self.assertEqual(run_one("screen_lock", self.stderr("screenLock is off")).status, Status.FAIL)

    def test_unrecognised(self):
        self.assertEqual(run_one("screen_lock", self.stderr("something new")).status, Status.ERROR)
        self.assertEqual(run_one("screen_lock", {}).status, Status.SKIP)


class SecurityUpdatesTests(unittest.TestCase):
    def test_defaults_when_unset_are_pass(self):
        self.assertEqual(run_one("security_updates", {}).status, Status.PASS)

    def test_disabled_locally(self):
        r = run_one("security_updates", {SU_LOCAL: (0, plist("<key>ConfigDataInstall</key><false/>"))})
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("ConfigDataInstall", r.summary)

    def test_managed_overrides_local(self):
        r = run_one("security_updates", {
            SU_LOCAL: (0, plist("<key>CriticalUpdateInstall</key><false/>")),
            SU_MANAGED: (0, plist("<key>CriticalUpdateInstall</key><true/>")),
        })
        self.assertEqual(r.status, Status.PASS)


class LoginWindowTests(unittest.TestCase):
    def test_guest(self):
        self.assertEqual(run_one("guest_account", {}).status, Status.PASS)
        self.assertEqual(run_one("guest_account", {LW_LOCAL: (0, plist("<key>GuestEnabled</key><true/>"))}).status,
                         Status.FAIL)
        self.assertEqual(run_one("guest_account", {
            LW_LOCAL: (0, plist("<key>GuestEnabled</key><true/>")),
            LW_MANAGED: (0, plist("<key>GuestEnabled</key><false/>")),
        }).status, Status.PASS)

    def test_auto_login_does_not_record_username(self):
        r = run_one("auto_login", {LW_LOCAL: (0, plist("<key>autoLoginUser</key><string>jdoe</string>"))})
        self.assertEqual(r.status, Status.FAIL)
        self.assertNotIn("jdoe", json.dumps(r.to_dict()))
        self.assertEqual(run_one("auto_login", {}).status, Status.PASS)


class AdminTests(unittest.TestCase):
    CMD = "/usr/bin/dscl . -read /Groups/admin GroupMembership"

    def test_counts_and_privacy(self):
        r = run_one("admin_accounts", {self.CMD: (0, "GroupMembership: root alice\n")})
        self.assertEqual(r.status, Status.PASS)
        self.assertEqual(r.details["admin_count"], 1)
        self.assertNotIn("alice", json.dumps(r.to_dict()))

    def test_include_usernames(self):
        r = run_one("admin_accounts", {self.CMD: (0, "GroupMembership: root bob alice\n")},
                    options=Options(include_usernames=True))
        self.assertEqual(r.details["admin_accounts"], ["alice", "bob"])

    def test_too_many(self):
        r = run_one("admin_accounts", {self.CMD: (0, "GroupMembership: root a b c d\n")})
        self.assertEqual(r.status, Status.WARN)

    def test_bad_output(self):
        self.assertEqual(run_one("admin_accounts", {self.CMD: (0, "No such key\n")}).status, Status.ERROR)


class XProtectTests(unittest.TestCase):
    def test_version(self):
        r = run_one("xprotect", {XPROTECT: (0, plist("<key>CFBundleShortVersionString</key><string>5284</string>"))})
        self.assertEqual(r.status, Status.INFO)
        self.assertEqual(r.details["version"], "5284")

    def test_missing(self):
        self.assertEqual(run_one("xprotect", {}).status, Status.SKIP)


class FrameworkTests(unittest.TestCase):
    def test_nothing_available_never_crashes(self):
        results = run_checks(Context(runner=fake_runner({}), now=NOW))
        self.assertEqual(len(results), 12)
        self.assertTrue(all(r.status in Status.ALL for r in results))

    def test_exceptions_become_errors(self):
        class Boom:
            def run(self, args, timeout=None):
                raise RuntimeError("synthetic")

        results = run_checks(Context(runner=Boom(), now=NOW))
        self.assertTrue(all(r.status == Status.ERROR for r in results))


if __name__ == "__main__":
    unittest.main()
