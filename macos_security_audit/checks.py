"""Security configuration checks. Every check is read-only."""

from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence

from .models import CheckResult, Outcome, Status, outcome
from .runner import CommandResult

FDESETUP = "/usr/bin/fdesetup"
CSRUTIL = "/usr/bin/csrutil"
SPCTL = "/usr/sbin/spctl"
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
SYSADMINCTL = "/usr/sbin/sysadminctl"
SYSTEMSETUP = "/usr/sbin/systemsetup"
PLUTIL = "/usr/bin/plutil"
DSCL = "/usr/bin/dscl"

SU_PREFS = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
SU_MANAGED = "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"
LOGINWINDOW = "/Library/Preferences/com.apple.loginwindow.plist"
LOGINWINDOW_MANAGED = "/Library/Managed Preferences/com.apple.loginwindow.plist"
XPROTECT_INFO = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"

SETTINGS = {
    "screen_lock_max_delay_seconds": 5,
    "admin_accounts_warn_above": 3,
}


@dataclass
class Options:
    include_usernames: bool = False


@dataclass
class Context:
    runner: Any
    now: datetime
    options: Options = field(default_factory=Options)


CheckFn = Callable[[Context], Outcome]
_REGISTRY: List[tuple] = []


def check(check_id: str, title: str, category: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY.append((check_id, title, category, fn))
        return fn
    return decorator


def available_checks() -> List[tuple]:
    return [(cid, title, cat) for cid, title, cat, _ in _REGISTRY]


def run_checks(ctx: Context, only: Optional[Sequence[str]] = None) -> List[CheckResult]:
    results = []
    for check_id, title, category, fn in _REGISTRY:
        if only and check_id not in only:
            continue
        try:
            res = fn(ctx)
        except Exception as exc:
            res = outcome(Status.ERROR, "Unexpected error while evaluating check: {}: {}".format(
                type(exc).__name__, exc))
        results.append(CheckResult(check_id, title, category, res.status, res.summary,
                                   dict(res.details), res.remediation))
    return results


def command_failure(result: CommandResult) -> Outcome:
    if result.not_found:
        return outcome(Status.SKIP, "Required command is unavailable on this system.",
                       command=result.command, error=result.describe_failure())
    if result.needs_privileges:
        return outcome(Status.SKIP, "Insufficient privileges to read this setting.",
                       "Re-run with sudo to evaluate this control.",
                       command=result.command, error=result.describe_failure())
    return outcome(Status.ERROR, result.describe_failure(), command=result.command)


def read_plist(ctx: Context, path: str) -> Optional[Dict[str, Any]]:
    res = ctx.runner.run([PLUTIL, "-convert", "xml1", "-o", "-", path])
    if not res.ok or not res.stdout.strip():
        return None
    try:
        data = plistlib.loads(res.stdout.encode("utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def merged_prefs(ctx: Context, local_path: str, managed_path: str) -> Dict[str, Any]:
    """Managed (MDM) values override local ones, as macOS applies them."""
    merged = dict(read_plist(ctx, local_path) or {})
    merged.update(read_plist(ctx, managed_path) or {})
    return merged


# --------------------------------------------------------------------------- data protection

@check("filevault", "FileVault disk encryption", "Data protection")
def check_filevault(ctx: Context) -> Outcome:
    res = ctx.runner.run([FDESETUP, "status"])
    if not res.ok:
        return command_failure(res)
    text = res.stdout
    fix = "Turn on FileVault in System Settings > Privacy & Security, or enforce it with an MDM profile."
    if "Encryption in progress" in text:
        pct = re.search(r"Percent completed = ([\d.]+)", text)
        return outcome(Status.WARN, "FileVault encryption in progress" + (
            " ({}%)".format(pct.group(1)) if pct else ""), "Allow encryption to finish.", state="encrypting")
    if "Decryption in progress" in text:
        return outcome(Status.FAIL, "FileVault is being turned off (decryption in progress)", fix,
                       state="decrypting")
    if "FileVault is On" in text:
        return outcome(Status.PASS, "FileVault is on", state="on")
    if "FileVault is Off" in text:
        return outcome(Status.FAIL, "FileVault is off", fix, state="off")
    return outcome(Status.ERROR, "Unrecognised fdesetup output.")


# --------------------------------------------------------------------------- system integrity

@check("sip", "System Integrity Protection", "System integrity")
def check_sip(ctx: Context) -> Outcome:
    res = ctx.runner.run([CSRUTIL, "status"])
    if not res.ok:
        return command_failure(res)
    text = res.stdout
    fix = "Boot to Recovery and run `csrutil enable`."
    if "Custom Configuration" in text:
        disabled = re.findall(r"^\s*([^:\n]+):\s*disabled", text, re.M)
        return outcome(Status.WARN, "SIP has a custom configuration", fix,
                       state="custom", disabled_components=[d.strip() for d in disabled])
    if "status: enabled" in text:
        return outcome(Status.PASS, "SIP is enabled", state="enabled")
    if "status: disabled" in text:
        return outcome(Status.FAIL, "SIP is disabled", fix, state="disabled")
    return outcome(Status.ERROR, "Unrecognised csrutil output.")


@check("gatekeeper", "Gatekeeper", "System integrity")
def check_gatekeeper(ctx: Context) -> Outcome:
    res = ctx.runner.run([SPCTL, "--status"])
    if res.error:
        return command_failure(res)
    text = res.stdout + res.stderr  # spctl exits 1 when disabled; judge by text
    if "assessments enabled" in text:
        return outcome(Status.PASS, "Gatekeeper assessments are enabled", state="enabled")
    if "assessments disabled" in text:
        return outcome(Status.FAIL, "Gatekeeper assessments are disabled",
                       "Re-enable Gatekeeper: `sudo spctl --global-enable` (or via MDM).", state="disabled")
    return command_failure(res) if res.returncode else outcome(Status.ERROR, "Unrecognised spctl output.")


@check("xprotect", "XProtect version", "System integrity")
def check_xprotect(ctx: Context) -> Outcome:
    info = read_plist(ctx, XPROTECT_INFO)
    if not info:
        return outcome(Status.SKIP, "XProtect bundle information not readable at the expected path.")
    version = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    return outcome(Status.INFO, "XProtect {}".format(version or "version unknown"), version=version)


@check("security_updates", "Automatic security updates", "System integrity")
def check_security_updates(ctx: Context) -> Outcome:
    prefs = merged_prefs(ctx, SU_PREFS, SU_MANAGED)
    # Both default to on when unset.
    critical = prefs.get("CriticalUpdateInstall", True)
    config = prefs.get("ConfigDataInstall", True)
    details = {"CriticalUpdateInstall": bool(critical), "ConfigDataInstall": bool(config),
               "explicitly_configured": sorted(k for k in ("CriticalUpdateInstall", "ConfigDataInstall") if k in prefs)}
    off = [k for k in ("CriticalUpdateInstall", "ConfigDataInstall") if not details[k]]
    if off:
        return Outcome(Status.FAIL, "Automatic security responses/data files disabled: {}".format(", ".join(off)),
                       details, "Turn on 'Install Security Responses and system files' in Software Update settings.")
    return Outcome(Status.PASS, "Security responses and system data files install automatically", details)


# --------------------------------------------------------------------------- network

def _firewall_state(text: str) -> Optional[int]:
    match = re.search(r"State = (\d)", text)
    if match:
        return int(match.group(1))
    if "is enabled" in text:
        return 1
    if "is disabled" in text:
        return 0
    return None


@check("firewall", "Application Firewall", "Network")
def check_firewall(ctx: Context) -> Outcome:
    res = ctx.runner.run([SOCKETFILTERFW, "--getglobalstate"])
    if not res.ok:
        return command_failure(res)
    state = _firewall_state(res.stdout)
    if state is None:
        return outcome(Status.ERROR, "Unrecognised socketfilterfw output.")
    if state == 0:
        return outcome(Status.FAIL, "Firewall is off",
                       "Turn on the firewall in System Settings > Network > Firewall, or via MDM.", state=0)
    label = "Firewall is on" + (" (blocking all incoming connections)" if state == 2 else "")
    return outcome(Status.PASS, label, state=state)


@check("firewall_stealth", "Firewall stealth mode", "Network")
def check_stealth(ctx: Context) -> Outcome:
    res = ctx.runner.run([SOCKETFILTERFW, "--getstealthmode"])
    if not res.ok:
        return command_failure(res)
    text = res.stdout.lower()
    if re.search(r"stealth mode (is )?(on|enabled)", text):
        return outcome(Status.PASS, "Stealth mode is on")
    if re.search(r"stealth mode (is )?(off|disabled)", text):
        return outcome(Status.WARN, "Stealth mode is off",
                       "Enable stealth mode so the Mac ignores ICMP probes and closed-port connection attempts.")
    return outcome(Status.ERROR, "Unrecognised socketfilterfw output.")


@check("remote_login", "Remote Login (SSH)", "Network")
def check_remote_login(ctx: Context) -> Outcome:
    res = ctx.runner.run([SYSTEMSETUP, "-getremotelogin"])
    text = res.stdout + res.stderr
    if "administrator access" in text.lower():
        return outcome(Status.SKIP, "Requires administrator privileges to read.",
                       "Re-run with sudo to evaluate this control.")
    if not res.ok:
        return command_failure(res)
    if re.search(r"Remote Login:\s*On", text):
        return outcome(Status.WARN, "Remote Login (SSH) is on",
                       "Disable Remote Login unless it is required and restricted to specific users.", state="on")
    if re.search(r"Remote Login:\s*Off", text):
        return outcome(Status.PASS, "Remote Login (SSH) is off", state="off")
    return outcome(Status.ERROR, "Unrecognised systemsetup output.")


# --------------------------------------------------------------------------- access control

@check("screen_lock", "Screen lock password", "Access control")
def check_screen_lock(ctx: Context) -> Outcome:
    res = ctx.runner.run([SYSADMINCTL, "-screenLock", "status"])
    # sysadminctl logs to stderr with a timestamp prefix and may exit 0 or 1.
    text = (res.stdout + "\n" + res.stderr)
    if res.error:
        return command_failure(res)
    max_delay = SETTINGS["screen_lock_max_delay_seconds"]
    fix = "Require a password immediately (or within {} s) after sleep or screen saver.".format(max_delay)
    if re.search(r"screenLock is off", text, re.I):
        return outcome(Status.FAIL, "Screen lock is off", fix, delay_seconds=None)
    if re.search(r"screenLock delay is immediate", text, re.I):
        return outcome(Status.PASS, "Password required immediately", delay_seconds=0)
    match = re.search(r"screenLock delay is (\d+) seconds?", text, re.I)
    if match:
        delay = int(match.group(1))
        status = Status.PASS if delay <= max_delay else Status.WARN
        return outcome(status, "Password required after {} seconds".format(delay),
                       "" if status == Status.PASS else fix, delay_seconds=delay)
    if res.needs_privileges or "authorization" in text.lower():
        return outcome(Status.SKIP, "Screen lock status requires a logged-in user context.")
    return command_failure(res) if not res.ok else outcome(Status.ERROR, "Unrecognised sysadminctl output.")


@check("guest_account", "Guest account", "Access control")
def check_guest(ctx: Context) -> Outcome:
    prefs = merged_prefs(ctx, LOGINWINDOW, LOGINWINDOW_MANAGED)
    enabled = bool(prefs.get("GuestEnabled", False))
    if enabled:
        return outcome(Status.FAIL, "Guest account is enabled",
                       "Disable the guest user in System Settings > Users & Groups.", guest_enabled=True)
    return outcome(Status.PASS, "Guest account is disabled", guest_enabled=False,
                   explicitly_configured="GuestEnabled" in prefs)


@check("auto_login", "Automatic login", "Access control")
def check_auto_login(ctx: Context) -> Outcome:
    prefs = merged_prefs(ctx, LOGINWINDOW, LOGINWINDOW_MANAGED)
    # The configured account name is deliberately not recorded.
    if prefs.get("autoLoginUser"):
        return outcome(Status.FAIL, "Automatic login is enabled",
                       "Turn off automatic login in System Settings > Users & Groups.", auto_login=True)
    return outcome(Status.PASS, "Automatic login is disabled", auto_login=False)


@check("admin_accounts", "Local administrator accounts", "Access control")
def check_admins(ctx: Context) -> Outcome:
    res = ctx.runner.run([DSCL, ".", "-read", "/Groups/admin", "GroupMembership"])
    if not res.ok:
        return command_failure(res)
    if not res.stdout.startswith("GroupMembership:"):
        return outcome(Status.ERROR, "Unrecognised dscl output.")
    members = sorted({m for m in res.stdout.split(":", 1)[1].split() if m != "root"})
    details: Dict[str, Any] = {"admin_count": len(members)}
    if ctx.options.include_usernames:
        details["admin_accounts"] = members
    limit = SETTINGS["admin_accounts_warn_above"]
    summary = "{} local administrator account(s) (excluding root)".format(len(members))
    if len(members) > limit:
        return Outcome(Status.WARN, summary, details,
                       "Review admin membership; standard accounts for daily use reduce risk.")
    if not members:
        return Outcome(Status.INFO, summary, details)
    return Outcome(Status.PASS, summary, details)
