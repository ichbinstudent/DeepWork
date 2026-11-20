# Troubleshooting

## Is the service running?

| | Linux | Windows |
| --- | --- | --- |
| Status | `systemctl status deepwork` | `sc query DeepWork`, or *Services* → DeepWork |
| Start | `sudo systemctl start deepwork` | `sc start DeepWork` (administrator terminal) |
| Log | `journalctl -u deepwork` | `C:\ProgramData\DeepWork\deepwork.log` (restarts after 1 MB) |
| Blocks and what's running | `deepworkctl status` | `deepworkctl status` |
| Version | `deepworkctl --version`, `deepwork-daemon --version` | the same, or *Settings → Apps* |

The app shows "Service offline" when it can't reach the service, with the command to start it.

## "You are not allowed to control DeepWork"

Only the user who installed DeepWork and administrators may control it.

- Linux: add your user id (`id -u`) to `allowed_users` in `/etc/deepwork/config.json` and run
  `sudo systemctl restart deepwork`.
- Windows: in an administrator terminal run `deepwork-daemon --allow-user <SID>` (your SID is in
  `whoami /user`), then `sc stop DeepWork` and `sc start DeepWork`.

If `config.json` is missing, broken or lists nobody, only administrators may control DeepWork
until it's fixed; the log says so.

## "Another program is posing as it" (Windows)

A program took the name of the service's connection (`\\.\pipe\deepwork`) while the service
wasn't running, so the app won't talk to it: it could be after your block passwords. Blocks are
still enforced. Restarting the computer ends that program; the log says when the service has its
name back. If it happens again, an administrator should find out which program it is.

## A site is still reachable

- Reload the page. Pages that were already open lose their connection when a block starts but
  stay on screen.
- Check that the hosts file has the site: `/etc/hosts` or
  `C:\Windows\System32\drivers\etc\hosts`, between the `DeepWork` markers.
- Browsers with their own encrypted DNS (secure DNS) or a VPN can get around the hosts file. In
  Chrome, Edge and Brave, `chrome://policy` (or `edge://policy`) should list `URLBlocklist`; click
  *Reload policies* if it doesn't. Firefox picks up its policy at its next start.
- On Linux, turn on the HTTPS filter in Settings to cover every app.

## An allowed site or app doesn't connect (Linux, HTTPS filter)

While websites are blocked, the HTTPS filter only lets a connection through if it names its site
and the name leads to the address it goes to (by the system's DNS). It refuses HTTPS to bare IP
addresses, plain HTTP to addresses outside your local network, and programs that look names up
some other way (their own DNS server, or addresses built in). That is on purpose: otherwise an
allowed name could carry a blocked site. Such programs work again when the block ends, or with the
HTTPS filter off in Settings (hardcore blocks keep it on).

## Sites stay blocked after a block ended

The service removes its entries when nothing is blocked any more. If the service was removed
without cleaning up (e.g. its files were deleted by hand), run as administrator:

- Linux: `sudo deepwork-daemon --cleanup`
- Windows: `"C:\Program Files\DeepWork\deepwork-daemon.exe" --cleanup`

This removes the hosts-file section, browser policies and firewall rules, and gives
administrator rights back after hardcore mode. As a last resort, delete the lines between the
`DeepWork` markers in the hosts file and the `URLBlocklist` policies.

## Locked out

Locks are meant to hold, but never forever:

- A block's lock ends when the block ends. *Until restart* ends with a restart.
- Hardcore mode (Linux) gives administrator rights back when it ends, and an independent timer
  does the same even if the service is gone. If something still fails, start a recovery shell
  (on most distributions: add `systemd.unit=rescue.target` to the kernel command line) and run
  `deepwork-daemon --cleanup`.
- On Windows, an administrator can stop the DeepWork service at any time.

## Corrupt or missing data

If the state file can't be read, the service keeps it as `state.json.corrupt` and continues with
the copy it made at its last start (`state.json.bak`). If the state was written by a newer
DeepWork, the service refuses to start instead of overwriting it; install the newer version
again.

## Reporting a bug

Open an issue with your system, how you installed DeepWork, its version, and the service log
around the time of the problem. Security problems: see [SECURITY.md](../SECURITY.md).
