#!/bin/bash
# Build DeepWork from source and install its service on macOS (experimental).
# Run as your normal user; the script uses sudo when it needs root.
set -euo pipefail
cd "$(dirname "$0")/.."

# Root's, unlike /usr/local with Homebrew on Intel Macs: the service runs as
# root, so nobody else may be able to replace it.
DIR=/Library/DeepWork
LABEL=io.github.ichbinstudent.DeepWork
JOB=/Library/LaunchDaemons/$LABEL.plist
CONFIG="/Library/Application Support/DeepWork/config.json"

if [[ $EUID -eq 0 ]]; then
    echo "Run macos/install.sh as your normal user (it uses sudo for the system parts)." >&2
    exit 1
fi
command -v cargo >/dev/null || { echo "cargo not found. Install Rust from https://rustup.rs" >&2; exit 1; }

echo "==> Building (release)…"
cargo build --release --locked -p deepwork-daemon
programs=(deepwork-daemon deepworkctl)
if command -v pkg-config >/dev/null && pkg-config --exists 'libadwaita-1 >= 1.7' 'gtk4 >= 4.14'; then
    cargo build --release --locked -p deepwork
    programs+=(deepwork)
else
    echo "Note: building the app needs GTK (brew install gtk4 libadwaita pkgconf);" >&2
    echo "only the service and deepworkctl are installed." >&2
fi

echo "==> Installing to $DIR (needs root)…"
sudo install -d -o root -g wheel -m 755 "$DIR"
for p in "${programs[@]}"; do
    # Replaced, not rewritten: the service may be running from the old file.
    sudo install -o root -g wheel -m 755 "target/release/$p" "$DIR/.$p.new"
    sudo mv -f "$DIR/.$p.new" "$DIR/$p"
done
sudo mkdir -p /usr/local/bin
for p in deepwork deepworkctl; do
    if [[ -x "$DIR/$p" ]]; then sudo ln -sf "$DIR/$p" "/usr/local/bin/$p"; fi
done
sudo install -o root -g wheel -m 755 macos/uninstall.sh "$DIR/uninstall.sh"
sudo install -o root -g wheel -m 644 LICENSE "$DIR/LICENSE"

# Only the installing user (and root) may control the service.
[[ -f "$CONFIG" ]] || sudo "$DIR/deepwork-daemon" --allow-user "$(id -u)"

echo "==> Starting the service…"
sudo launchctl bootout "system/$LABEL" 2>/dev/null || true
sudo install -o root -g wheel -m 644 "macos/$LABEL.plist" "$JOB"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sudo launchctl bootstrap system "$JOB" 2>/dev/null && break
    sleep 1 # the old one is still stopping
done
sudo launchctl print "system/$LABEL" >/dev/null || { echo "The service didn't start." >&2; exit 1; }

echo
echo "DeepWork is installed. Command line: deepworkctl status"
echo "To uninstall: $DIR/uninstall.sh [--purge]"
