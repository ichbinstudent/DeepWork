#!/bin/bash
# Install DeepWork from source on a macOS CI runner, block a site and apps,
# update with a locked block, and uninstall.
set -euo pipefail
fail() {
    echo "FAILED: $*" >&2
    cat /Library/Logs/DeepWork.log >&2 || true
    exit 1
}
ok() { echo "ok: $*"; }
answers() {
    for _ in $(seq 40); do
        deepworkctl status >/dev/null 2>&1 && return
        sleep 0.25
    done
    return 1
}
# Wait for a command to succeed.
until_ok() {
    for _ in $(seq 60); do
        "$@" && return
        sleep 0.25
    done
    return 1
}
gone() { ! kill -0 "$1" 2>/dev/null; }

macos/install.sh
answers || fail "the service answers"
ok "installed, the service answers"
[[ "$(stat -f %Su:%Sg:%Lp /Library/DeepWork/deepwork-daemon)" == root:wheel:755 ]] || fail "the service's program belongs to root"
grep -q "\b$(id -u)\b" "/Library/Application Support/DeepWork/config.json" || fail "the installing user may control it"

# An app bundle and a plain program to block, and one to leave alone.
work=$(mktemp -d)
app="$work/Blocked Game.app"
mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.example.blockedgame</string>
<key>CFBundleExecutable</key><string>game</string>
</dict></plist>
EOF
for p in "$app/Contents/MacOS/game" "$work/blockme" "$work/keepme"; do
    printf '#include <unistd.h>\nint main(void) { sleep(600); return 0; }\n' | cc -x c -o "$p" -
done
start() {
    "$app/Contents/MacOS/game" &
    game=$!
    "$work/blockme" &
    plain=$!
}
start
"$work/keepme" &
keep=$!
disown -a

deepworkctl add Test example.com app:org.example.blockedgame app:blockme
deepworkctl start Test 5
until_ok gone "$game" || fail "the running app is closed (by bundle id)"
until_ok gone "$plain" || fail "the running program is closed (by name)"
until_ok grep -q '0\.0\.0\.0 example\.com' /etc/hosts || fail "hosts file blocks example.com"
ok "blocking a website, and closing an app and a program that were running"
start
disown -a
until_ok gone "$game" || fail "the app is closed when started"
until_ok gone "$plain" || fail "the program is closed when started"
kill -0 "$keep" || fail "another program keeps running"
ok "closing them when they start, and nothing else"
deepworkctl status
kill "$keep"
deepworkctl stop Test
start
disown -a
sleep 5
kill -0 "$game" || fail "the app runs after the block"
kill "$game" "$plain"
! grep -q 'example\.com' /etc/hosts || fail "hosts file is clean after the block"
ok "everything is back after the block"

deepworkctl add Locked --lock strict example.org
deepworkctl start Locked 5
until_ok grep -q 'example\.org' /etc/hosts || fail "hosts file blocks example.org"
macos/install.sh >/dev/null
answers || fail "the service answers after an update"
deepworkctl locked || fail "still locked after an update"
if /Library/DeepWork/uninstall.sh; then fail "uninstalled while locked"; fi
[[ -x /Library/DeepWork/deepwork-daemon ]] || fail "still installed"
ok "an update keeps the lock, and uninstalling is refused"

# Forget the locked block (the test can't wait for it), then uninstall.
sudo launchctl bootout system/io.github.ichbinstudent.DeepWork
sleep 2
sudo rm "/Library/Application Support/DeepWork/state/state.json"
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.ichbinstudent.DeepWork.plist
answers || fail "the service runs without the lock"
/Library/DeepWork/uninstall.sh --purge
[[ ! -e /Library/DeepWork && ! -e "/Library/Application Support/DeepWork" ]] || fail "removed"
! grep -q 'example\.' /etc/hosts || fail "hosts file clean"
! sudo launchctl print system/io.github.ichbinstudent.DeepWork >/dev/null 2>&1 || fail "service removed"
ok "uninstalled"
echo "All macOS checks passed."
