#!/bin/sh
# After installing or updating DeepWork (deb: postinst, rpm: %post).
set -e

# Who may control DeepWork: the user who ran the package manager through
# sudo, pkexec or run0. Others: deepwork-daemon --allow-user <uid>.
user="${SUDO_UID:-${PKEXEC_UID:-}}"
if [ -n "$user" ] && [ "$user" != 0 ]; then
    deepwork-daemon --allow-user "$user" >/dev/null || true
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable deepwork.service >/dev/null 2>&1 || true
    # Start, or restart with the new version after an update.
    systemctl restart deepwork.service || true
fi
gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database -q /usr/share/applications 2>/dev/null || true
exit 0
