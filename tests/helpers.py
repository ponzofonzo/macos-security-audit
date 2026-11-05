"""Test helpers: fake runners built from synthetic command output."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from macos_security_audit.checks import Context, Options, run_checks
from macos_security_audit.runner import ReplayRunner

NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "examples", "fixtures")

PLUTIL = "/usr/bin/plutil -convert xml1 -o - "
SU_LOCAL = PLUTIL + "/Library/Preferences/com.apple.SoftwareUpdate.plist"
SU_MANAGED = PLUTIL + "'/Library/Managed Preferences/com.apple.SoftwareUpdate.plist'"
LW_LOCAL = PLUTIL + "/Library/Preferences/com.apple.loginwindow.plist"
LW_MANAGED = PLUTIL + "'/Library/Managed Preferences/com.apple.loginwindow.plist'"
XPROTECT = PLUTIL + "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"


def plist(body):
    return '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>{}</dict></plist>'.format(body)


def fake_runner(mapping):
    commands = {}
    for cmd, value in mapping.items():
        commands[cmd] = {"returncode": value[0], "stdout": value[1],
                         "stderr": value[2] if len(value) > 2 else ""}
    return ReplayRunner(commands)


def run_one(check_id, mapping, options=None):
    ctx = Context(runner=fake_runner(mapping), now=NOW, options=options or Options())
    results = run_checks(ctx, only=[check_id])
    assert len(results) == 1
    return results[0]
