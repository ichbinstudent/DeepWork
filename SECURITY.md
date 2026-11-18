# Security policy

DeepWork runs a service with full administrator rights (root on Linux, SYSTEM on Windows), so
security problems matter. Please report them privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. Please don't open a public issue for security problems.

Include what you found, how to reproduce it, the DeepWork version, and your operating system.
You'll get an answer within a week. Fixes for confirmed problems go into a release as soon as
possible, and you'll be credited in the release notes unless you'd rather not be.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope: anything that lets a user who isn't allowed to control DeepWork change or end blocks,
anything that lets a user gain rights through the service, the installer or the app, and anything
that makes the service damage the system (hosts file, browser policies, firewall, user accounts).

Out of scope: an administrator (root) ending their own blocks. DeepWork can't stop that; see
[the known limitations](docs/PLATFORMS.md#known-limitations).
