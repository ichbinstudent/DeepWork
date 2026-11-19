#!/bin/sh
# After installing or updating DeepWork (deb: postinst, rpm: %post).
set -e

# Who may control DeepWork: the user who ran the package manager through
# sudo, pkexec, run0 or doas. Others: deepwork-daemon --allow-user <uid>.
# Without anyone listed, only root may control it.
user="${SUDO_UID:-${PKEXEC_UID:-}}"
if [ -z "$user" ] && [ -n "${DOAS_USER:-}" ]; then
    user=$(id -u "$DOAS_USER" 2>/dev/null || true)
fi
if [ -n "$user" ] && [ "$user" != 0 ]; then
    deepwork-daemon --allow-user "$user" >/dev/null || true
elif ! cat /etc/deepwork/config.json 2>/dev/null | tr -d ' \n' | grep -q '"allowed_users":\[[0-9]'; then
    echo "DeepWork: only root may control it. To let a user in, run" >&2
    echo "  deepwork-daemon --allow-user <uid> && systemctl restart deepwork" >&2
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
