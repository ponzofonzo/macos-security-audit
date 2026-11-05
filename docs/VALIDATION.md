# Real-Mac validation checklist

Automated tests use **synthetic** command output. Confirm each control on physical Macs (ideally
one MDM-managed and one unmanaged) on every macOS major version you support. Turn anonymized real
output into new fixtures.

```bash
python3 -m macos_security_audit --html /tmp/user.html
sudo python3 -m macos_security_audit --html /tmp/root.html --include-usernames
```

| Control | Confirm on a real Mac |
|---------|-----------------------|
| `filevault` | Matches `fdesetup status`. If possible, catch the "Encryption in progress" state on a test Mac. |
| `sip` | Matches `csrutil status`. |
| `gatekeeper` | Matches `spctl --status`. Newer macOS versions restrict `--global-disable`, so test the disabled state only where it's allowed. |
| `xprotect` | The `Info.plist` path exists on your macOS version and the version matches `system_profiler SPInstallHistoryDataType \| grep -A3 XProtect`. On macOS 15+, compare with `xprotect version`. |
| `security_updates` | Toggle "Install Security Responses and system files" and confirm the result changes. Confirm a Jamf Software Update payload overrides the local value. |
| `firewall` / `firewall_stealth` | Toggle in System Settings > Network > Firewall. Check that your macOS version's wording still parses: both "stealth mode is on" and "Stealth mode enabled" forms are supported. |
| `remote_login` | Without sudo → `skip`. With sudo, it matches System Settings > General > Sharing > Remote Login. On some macOS versions, `systemsetup` also needs Full Disk Access for the terminal. |
| `screen_lock` | Run it as the logged-in user and compare with Lock Screen settings. Record what it reports under sudo and from a Jamf policy, since it's user-context dependent. |
| `guest_account` / `auto_login` | Toggle in Users & Groups. Confirm the auto-login username never appears in the report. |
| `admin_accounts` | Count matches Users & Groups. Names appear only with `--include-usernames`. |
