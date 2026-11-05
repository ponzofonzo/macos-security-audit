# macOS Security Audit

[![CI](https://github.com/ponzofonzo/macos-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ponzofonzo/macos-security-audit/actions/workflows/ci.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)

A read-only audit of core macOS security settings: FileVault, SIP, Gatekeeper, the application
firewall, automatic security updates, screen lock, guest access, automatic login, SSH, and local
admin accounts. It writes a console summary, a JSON report, and a self-contained HTML report, and
gives a simple score.

- **Read-only.** It only runs status and read commands. A unit test fails the build if a mutating
  flag (`--set…`, `enable`, `disable`, `write`, `-create`, `-delete`, …) is ever passed.
- **No dependencies.** Python 3.9+ standard library only.
- **Honest about gaps.** Anything it can't read, because of missing privileges, a missing tool, or
  unexpected output, is reported as `skip` or `error` and left out of the score. It is never
  counted as passing.
- **Privacy-conscious.** Admin account names and the auto-login username are left out unless you
  pass `--include-usernames`. The auto-login username is never included.

## Controls

| ID | Category | Pass | Warn | Fail | Source |
|----|----------|------|------|------|--------|
| `filevault` | Data protection | On | Encrypting | Off / Decrypting | `fdesetup status` |
| `sip` | System integrity | Enabled | Custom config | Disabled | `csrutil status` |
| `gatekeeper` | System integrity | Enabled | — | Disabled | `spctl --status` |
| `xprotect` | System integrity | *info: version* | | | XProtect bundle `Info.plist` |
| `security_updates` | System integrity | Security Responses and system data files install automatically | — | Either one off | `com.apple.SoftwareUpdate` (local + managed) |
| `firewall` | Network | On / Block all | — | Off | `socketfilterfw --getglobalstate` |
| `firewall_stealth` | Network | On | Off | — | `socketfilterfw --getstealthmode` |
| `remote_login` | Network | Off | On | — | `systemsetup -getremotelogin` (**needs sudo**) |
| `screen_lock` | Access control | Immediate or ≤ 5 s | > 5 s | Off | `sysadminctl -screenLock status` |
| `guest_account` | Access control | Disabled | — | Enabled | `com.apple.loginwindow` (local + managed) |
| `auto_login` | Access control | Disabled | — | Enabled | `com.apple.loginwindow` |
| `admin_accounts` | Access control | 1–3 admins | > 3 | — | `dscl . -read /Groups/admin` |

Settings delivered by MDM configuration profiles (`/Library/Managed Preferences`) take precedence
over local preferences, just as macOS applies them. You can tune the thresholds in `SETTINGS` in
[`macos_security_audit/checks.py`](macos_security_audit/checks.py).

**Score** = passing controls ÷ evaluated controls (`pass` + `warn` + `fail`). `info`, `skip`, and
`error` results are excluded and listed as `not_evaluated` in the JSON summary.

> This tool is a quick posture check. It isn't a compliance benchmark and doesn't replace one. For
> CIS- or NIST-aligned baselines, see the macOS Security Compliance Project (mSCP).

## Requirements

- macOS with `python3` 3.9 or newer.
- Run it with `sudo` for full coverage. Without root, `remote_login` reports `skip`.
- `screen_lock` reads the setting for the **user who runs the command**. When run as root or from
  a Jamf policy, it may not reflect the logged-in user's setting.

## Usage

```bash
git clone https://github.com/ponzofonzo/macos-security-audit.git
cd macos-security-audit

python3 -m macos_security_audit                                # console summary
sudo python3 -m macos_security_audit --json a.json --html a.html
python3 -m macos_security_audit --check filevault --check firewall
python3 -m macos_security_audit --fail-on fail --quiet         # exit 1 if any control fails
python3 -m macos_security_audit --json - | jq '.summary.score_percent'
```

| Option | Meaning |
|--------|---------|
| `--json PATH` / `--html PATH` | Write reports (`-` = JSON to stdout). |
| `--include-usernames` | Add admin account names to the `admin_accounts` details. |
| `--check ID` | Run only this control. You can repeat it. `--list-checks` shows the IDs. |
| `--fail-on never\|warn\|fail` | Exit-code policy. |
| `--timeout SECONDS` | Timeout for each command. |
| `--replay FIXTURE` | Render from synthetic or recorded output (any OS). |

**Exit codes:** `0` success · `1` the `--fail-on` threshold was hit · `2` invalid arguments ·
`3` fatal.

## Examples

Rendered from **synthetic fixtures** in [`examples/fixtures/`](examples/fixtures/):

| Scenario | Report |
|----------|--------|
| Managed Mac meeting the baseline (run with sudo) | [`hardened-report.html`](examples/hardened-report.html) / [`.json`](examples/hardened-report.json) |
| Unmanaged Mac with weak settings (run without sudo) | [`at-risk-report.html`](examples/at-risk-report.html) / [`.json`](examples/at-risk-report.json) |

## Testing

| Layer | Where it runs | What it proves |
|-------|---------------|----------------|
| Unit tests with mocked output | Any OS: `python3 -m unittest discover -s tests -t .` | Parsing of every state above, managed-over-local precedence, privilege and failure handling, score math, username privacy, read-only guard, HTML escaping |
| Replay fixtures | Any OS | End-to-end JSON/HTML generation |
| CI live smoke run | GitHub-hosted `macos-latest` VM, as a user and as root | The tool runs against real macOS commands and produces a valid report |
| **Manual validation** | **Physical Macs** | Parsers match real output on your macOS versions; managed profiles are reflected correctly |

Mocked outputs are synthetic and modeled on each command's documented or commonly observed format.
See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the real-Mac checklist.

## About this project

I've built tooling like this for employers during my career; that code belongs to them. This
repository is a generic version written independently, from scratch, for public use. It contains
no employer source code, configurations, credentials, device data, or internal information, and it
relies only on built-in macOS commands and publicly documented behavior.

## License

MIT. See [LICENSE](LICENSE).
