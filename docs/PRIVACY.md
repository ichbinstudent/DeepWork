# Privacy

DeepWork runs entirely on your computer. It has no account, no telemetry, no analytics, no crash
reporting and no ads, and it never sends anything about you anywhere.

## What it stores

| What | Where | Who can read it |
| --- | --- | --- |
| Blocks (names, websites, apps, schedules, locks) and settings | Linux: `/var/lib/deepwork/state.json`; Windows: `C:\ProgramData\DeepWork\state\state.json` | root / administrators only |
| Statistics: focus time per day, how often each blocked app was closed | the same file | the same |
| Lock passwords | the same file, as salted hashes (never the password itself) | the same |
| Who may control DeepWork (user ids or SIDs) | Linux: `/etc/deepwork/config.json`; Windows: `C:\ProgramData\DeepWork\config.json` | readable by all users |
| The service's log (starts, errors, closed connections; no browsing history) | Linux: the systemd journal; Windows: `C:\ProgramData\DeepWork\deepwork.log` | administrators (Linux: per journal settings) |
| The app's own preferences (e.g. whether the top bar shows a timer) | `~/.config/deepwork/` or `%LOCALAPPDATA%\deepwork\` | you |

DeepWork doesn't record which websites you visit. The HTTPS filter (Linux, off by default) looks
at the name of each site a connection goes to, to refuse blocked ones; it doesn't keep it, and it
never decrypts anything.

## Network

DeepWork itself only makes DNS lookups for sites you block, so it can close connections that are
already open to them. It doesn't check for updates or download anything.

Uninstalling with "delete my data" (Linux: `--purge`, Windows: the uninstaller's question or
`/PURGE=1`) removes everything listed above.
