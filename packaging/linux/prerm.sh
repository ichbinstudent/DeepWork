#!/bin/sh
# Before removing DeepWork (deb: prerm, rpm: %preun). Removal is refused
# while a block is locked; updates go ahead (locks survive them).
set -e
case "$1" in
    remove | 0) ;;
    *) exit 0 ;;
esac
if deepworkctl locked >/dev/null 2>&1; then
    echo "DeepWork: a block is locked or a freeze is running. Remove DeepWork again when it's over." >&2
    exit 1
fi
if [ -d /run/systemd/system ]; then
    systemctl disable --now deepwork.service >/dev/null 2>&1 || true
fi
# Take the blocks out of the hosts file, browsers and firewall.
deepwork-daemon --cleanup >/dev/null 2>&1 || true
exit 0
