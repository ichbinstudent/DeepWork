#!/bin/sh
# After removing DeepWork (deb: postrm, rpm: %postun). `apt purge` also
# deletes blocks, statistics and settings; with rpm they stay in
# /var/lib/deepwork and /etc/deepwork.
set -e
if [ "$1" = purge ]; then
    rm -rf /var/lib/deepwork /etc/deepwork
fi
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database -q /usr/share/applications 2>/dev/null || true
exit 0
