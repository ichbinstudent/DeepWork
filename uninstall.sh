#!/usr/bin/env bash
# Remove DeepWork. Refuses while a block is locked or a freeze is running.
#   --purge   also delete blocks, statistics and settings
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share"
# Run a command as root with sudo, doas or run0 (or $SUDO).
if [[ -z "${SUDO:-}" ]]; then
    for c in sudo doas run0; do
        command -v "$c" >/dev/null && SUDO=$c && break
    done
fi
[[ -n "${SUDO:-}" ]] || { echo "Needs sudo, doas or run0 (or set SUDO)." >&2; exit 1; }
PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

if command -v deepworkctl >/dev/null && deepworkctl locked 2>/dev/null; then
    echo "A block is locked or a freeze is running. Uninstall again when it's over." >&2
    deepworkctl status || true
    exit 1
fi

pkill -x deepwork 2>/dev/null || true
$SUDO systemctl disable --now deepwork.service 2>/dev/null || true
# Remove our /etc/hosts section and browser policies.
$SUDO "$BINDIR/deepwork-daemon" --cleanup || true

$SUDO rm -f "$BINDIR/deepwork" "$BINDIR/deepwork-daemon" "$BINDIR/deepworkctl" \
    "$DATADIR/applications/io.github.ichbinstudent.DeepWork.desktop" \
    "$DATADIR/icons/hicolor/scalable/apps/io.github.ichbinstudent.DeepWork.svg" \
    /etc/xdg/autostart/io.github.ichbinstudent.DeepWork-autostart.desktop \
    /etc/systemd/system/deepwork.service
$SUDO rm -rf "$PREFIX/lib/deepwork" "$DATADIR/doc/deepwork"
$SUDO systemctl daemon-reload

if [[ $PURGE -eq 1 ]]; then
    $SUDO rm -rf /var/lib/deepwork /etc/deepwork
    echo "DeepWork and all its data were removed."
else
    echo "DeepWork was removed. Your blocks are kept in /var/lib/deepwork (use --purge to delete them)."
fi
