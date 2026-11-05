# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-11-05

### Added
- Twelve read-only controls: FileVault, SIP, Gatekeeper, XProtect version, automatic security
  updates, firewall, stealth mode, Remote Login, screen lock, guest account, automatic login, and
  local admin accounts.
- Managed preferences (MDM profiles) take precedence over local preferences.
- Security score with not-evaluated controls listed separately.
- JSON, self-contained HTML, and console reports. Replay mode for synthetic fixtures.
- Admin usernames left out by default (`--include-usernames` to opt in).
- Unit tests with mocked command output, including a guard against commands that change settings.
