#!/usr/bin/env bash
# Install, use, update and remove a DeepWork .deb or .rpm in a container, as
# root. Containers have no systemd, so the test runs the service itself.
#   linux-package-test.sh PACKAGE
set -euo pipefail
pkg=$(realpath "$1")
fail() {
    echo "FAILED: $*" >&2
    exit 1
}
ok() { echo "ok: $*"; }

if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    install() { apt-get install -y -q "$pkg"; }
    reinstall() { apt-get install -y -q --reinstall "$pkg"; }
    remove() { apt-get remove -y -q deepwork; }
    purge() { apt-get purge -y -q deepwork; }
    purges=1
else
    install() { dnf install -y -q "$pkg"; }
    reinstall() { dnf reinstall -y -q "$pkg"; }
    remove() { dnf remove -y -q deepwork; }
    purge() { :; }
    purges=0
fi

# Installing pulls in the dependencies and records who installed it.
SUDO_UID=4242 install || fail "install"
for p in deepwork deepwork-daemon deepworkctl; do
    "$p" --version | grep -q "$p 0" || fail "$p --version"
done
ok "installed, programs run (libraries found)"
grep -q 'ExecStart=/usr/bin/deepwork-daemon' /usr/lib/systemd/system/deepwork.service || fail "service unit"
test -f /usr/share/metainfo/io.github.ichbinstudent.DeepWork.metainfo.xml || fail "AppStream metadata"
# Container images skip documentation when installing, so ask the package.
files=$(if command -v dpkg >/dev/null; then dpkg -L deepwork; else rpm -ql deepwork; fi)
for f in THIRD-PARTY-NOTICES.txt deepworkctl.1.gz deepwork-daemon.8.gz; do
    grep -q "/$f$" <<<"$files" || fail "$f in the package"
done
ok "service unit, desktop metadata and notices installed"
if grep -q 4242 /etc/deepwork/config.json 2>/dev/null; then
    ok "the installing user (SUDO_UID) may control DeepWork"
elif [[ $purges == 1 ]]; then
    fail "SUDO_UID not recorded"
else
    echo "note: this package manager doesn't pass SUDO_UID to scripts"
fi

start_service() {
    /usr/bin/deepwork-daemon >/tmp/deepwork.log 2>&1 &
    service=$!
    for _ in $(seq 40); do
        deepworkctl status >/dev/null 2>&1 && return
        sleep 0.25
    done
    cat /tmp/deepwork.log
    fail "service doesn't answer"
}
stop_service() {
    kill "$service" 2>/dev/null || true
    wait "$service" 2>/dev/null || true
}
start_service

deepworkctl add Test example.com >/dev/null
deepworkctl start Test 5 >/dev/null
for _ in $(seq 40); do
    grep -q '0.0.0.0 example.com' /etc/hosts && break
    sleep 0.25
done
grep -q '0.0.0.0 example.com' /etc/hosts || {
    cat /tmp/deepwork.log
    fail "hosts file blocks example.com"
}
ok "blocking example.com"

deepworkctl add Locked --lock strict example.org >/dev/null
deepworkctl start Locked 5 >/dev/null
if remove; then fail "removal goes ahead while a block is locked"; fi
test -x /usr/bin/deepwork-daemon || fail "still installed"
ok "removal refused while a block is locked"

reinstall || fail "update (reinstall)"
deepworkctl locked || fail "lock kept through the update"
deepworkctl status | grep -q Test || fail "blocks kept through the update"
ok "update keeps blocks and the lock"

# Forget the locked block (the test can't wait for it), then remove.
stop_service
rm /var/lib/deepwork/state.json
start_service
remove || fail "remove"
stop_service
test ! -e /usr/bin/deepwork-daemon || fail "programs removed"
! grep -q 'example\.' /etc/hosts || fail "hosts file cleaned"
ok "removed, hosts file clean"
if [[ $purges == 1 ]]; then
    test -d /var/lib/deepwork || fail "data kept after remove"
    purge || fail "purge"
    test ! -e /var/lib/deepwork -a ! -e /etc/deepwork || fail "purge deletes the data"
    ok "purge deletes the data"
fi
echo "All package checks passed."
