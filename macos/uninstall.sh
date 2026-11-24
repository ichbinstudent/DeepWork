#!/bin/bash
# Remove DeepWork from macOS. Refuses while a block is locked.
#   --purge   also delete blocks, statistics and settings
set -euo pipefail
DIR=/Library/DeepWork
LABEL=io.github.ichbinstudent.DeepWork
DATA="/Library/Application Support/DeepWork"

if "$DIR/deepworkctl" locked 2>/dev/null; then
    echo "A block is locked. Uninstall again when it's over." >&2
    "$DIR/deepworkctl" status || true
    exit 1
fi

pkill -x deepwork 2>/dev/null || true
sudo launchctl bootout "system/$LABEL" 2>/dev/null || true
sudo rm -f "/Library/LaunchDaemons/$LABEL.plist"
# Remove our hosts section and browser policies.
sudo "$DIR/deepwork-daemon" --cleanup || true
for p in deepwork deepworkctl; do
    if [[ "$(readlink "/usr/local/bin/$p" 2>/dev/null)" == "$DIR/$p" ]]; then
        sudo rm -f "/usr/local/bin/$p"
    fi
done
sudo rm -rf "$DIR"

if [[ "${1:-}" == "--purge" ]]; then
    sudo rm -rf "$DATA" /Library/Logs/DeepWork.log
    echo "DeepWork and all its data were removed."
else
    echo "DeepWork was removed. Your blocks are kept in $DATA (use --purge to delete them)."
fi
