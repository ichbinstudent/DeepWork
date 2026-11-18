#!/usr/bin/env bash
# Build the Linux packages from release binaries: the tarball (install.sh),
# a .deb and an .rpm (with nfpm, downloaded here at a pinned version).
#   package-linux.sh BIN_DIR OUT_DIR
set -euo pipefail
bin=$1
out=$2
NFPM_VERSION=2.49.0
NFPM_SHA256=2afaa5ffb5e3493402e31e7c67a5a1fb42133e3f66fc315ca0051934125561c7

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 .github/scripts/third_party_notices.py "$work/THIRD-PARTY-NOTICES.txt"

# Stripped programs; their debug information goes into a separate archive
# (linked by .gnu_debuglink).
name="deepwork-$version-linux-x86_64"
mkdir -p "$work/stripped" "$work/$name-debug"
for f in deepwork deepwork-daemon deepworkctl; do
    objcopy --only-keep-debug "$bin/$f" "$work/$name-debug/$f.debug"
    strip --strip-debug --strip-unneeded -o "$work/stripped/$f" "$bin/$f"
    (cd "$work/$name-debug" && objcopy --add-gnu-debuglink="$f.debug" "$work/stripped/$f")
done
tar -C "$work" -czf "$out/$name-debug.tar.gz" "$name-debug"
bin="$work/stripped"

# Tarball with the install script.
mkdir -p "$work/$name/bin" "$work/$name/assets"
cp "$bin/deepwork" "$bin/deepwork-daemon" "$bin/deepworkctl" "$work/$name/bin/"
cp -r data "$work/$name/"
cp assets/icon.svg "$work/$name/assets/"
cp install.sh uninstall.sh README.md LICENSE "$work/THIRD-PARTY-NOTICES.txt" "$work/$name/"
tar -C "$work" -czf "$out/$name.tar.gz" "$name"

# The newest glibc symbol version the binaries need.
glibc=$(objdump -T "$bin"/deepwork "$bin"/deepwork-daemon "$bin"/deepworkctl |
    grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1)

# Set PACKAGE_MAINTAINER (a repository variable in CI) to a real address.
maintainer="${PACKAGE_MAINTAINER:-DeepWork contributors <maintainer@deepwork.invalid>}"
stage="$work/stage"
mkdir -p "$stage/bin"
cp "$bin/deepwork" "$bin/deepwork-daemon" "$bin/deepworkctl" "$stage/bin/"
sed "s|@BINDIR@|/usr/bin|" data/deepwork.service >"$stage/deepwork.service"
cp "$work/THIRD-PARTY-NOTICES.txt" "$stage/"
cat >"$stage/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: DeepWork
Source: https://github.com/ichbinstudent/deepwork

Files: *
Copyright: 2026 DeepWork contributors
License: GPL-3.0-or-later
 On Debian systems, the full text of the GNU General Public License
 version 3 can be found in /usr/share/common-licenses/GPL-3.
 .
 The Rust libraries built into the programs are listed, with their
 licenses, in /usr/share/doc/deepwork/THIRD-PARTY-NOTICES.txt.
COPYRIGHT
# Reproducible: dates and gzip headers come from the last commit.
when=$(git log -1 --format=%ct 2>/dev/null || date +%s)
mkdir -p "$stage/man"
for m in packaging/linux/man/*; do
    gzip -9n <"$m" >"$stage/man/$(basename "$m").gz"
done
{
    echo "deepwork ($version-1) unstable; urgency=medium"
    echo
    echo "  * DeepWork $version. See /usr/share/doc/deepwork/README.md and"
    echo "    https://github.com/ichbinstudent/deepwork/blob/main/CHANGELOG.md"
    echo
    echo " -- $maintainer  $(LC_ALL=C date -u -R -d "@$when")"
} | gzip -9n >"$stage/changelog.Debian.gz"

nfpm=$(command -v nfpm || true)
if [[ -z "$nfpm" ]]; then
    curl -sSfL -o "$work/nfpm.tar.gz" \
        "https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
    echo "$NFPM_SHA256  $work/nfpm.tar.gz" | sha256sum -c -
    tar -C "$work" -xzf "$work/nfpm.tar.gz" nfpm
    nfpm="$work/nfpm"
fi
sed -e "s|\${VERSION}|$version|g" -e "s|\${GLIBC}|$glibc|g" -e "s|\${STAGE}|$stage|g" \
    -e "s|\${MAINTAINER}|$maintainer|g" packaging/linux/nfpm.yaml >"$work/nfpm.yaml"
"$nfpm" package --config "$work/nfpm.yaml" --packager deb --target "$out/deepwork_${version}-1_amd64.deb"
"$nfpm" package --config "$work/nfpm.yaml" --packager rpm --target "$out/deepwork-${version}-1.x86_64.rpm"
ls -la "$out"
