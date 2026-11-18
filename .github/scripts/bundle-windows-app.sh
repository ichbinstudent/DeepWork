#!/usr/bin/env bash
# Collect the GTK app and everything it needs from MSYS2 (UCRT64 or
# CLANGARM64) into DIR:
# DLLs, the SVG image loader, icons and GSettings schemas. GTK finds share/
# and lib/ next to its DLLs, so the folder works wherever it is copied.
#   usage (in an MSYS2 shell, after cargo build --release -p deepwork):
#   bundle-windows-app.sh DIR
set -euxo pipefail
lap() { echo "[bundle] $1 after ${SECONDS}s"; }
out=$1
prefix=${MINGW_PREFIX:?run this in an MSYS2 shell}
mkdir -p "$out"
cp "${CARGO_TARGET_DIR:-target}/release/deepwork.exe" windows/deepwork.ico "$out/"
# The app's debug information goes next to the bundle (DIR-symbols), out of
# the package.
objcopy=$(command -v llvm-objcopy || command -v objcopy)
strip=$(command -v llvm-strip || command -v strip)
mkdir -p "$out-symbols"
"$objcopy" --only-keep-debug "$out/deepwork.exe" "$out-symbols/deepwork.exe.debug"
"$strip" --strip-debug "$out/deepwork.exe"
(cd "$out-symbols" && "$objcopy" --add-gnu-debuglink=deepwork.exe.debug "../$out/deepwork.exe") ||
    echo "no debug link"


# The SVG loader (icons are SVG) and a template of its loader list; the app
# fills in the absolute path at start-up.
loaders=lib/gdk-pixbuf-2.0/2.10.0
mkdir -p "$out/$loaders/loaders"
ls "$prefix/$loaders/loaders/"
cp "$prefix/$loaders/loaders/"*svg*.dll "$out/$loaders/loaders/"
gdk-pixbuf-query-loaders "$out/$loaders/loaders/"*.dll >"$out/loaders.cache.tmp"
cat "$out/loaders.cache.tmp"
# Replace the folder in each loader's path (the first quoted string of a
# loader entry) with the placeholder.
sed -E 's#^"[^"]*[\\/]([^"\\/]+\.dll)"#"@LOADERS_DIR@/\1"#' "$out/loaders.cache.tmp" >"$out/$loaders/loaders.cache.in"
rm "$out/loaders.cache.tmp"
cat "$out/$loaders/loaders.cache.in"
grep -q '@LOADERS_DIR@' "$out/$loaders/loaders.cache.in"

# Every MSYS2 DLL that the app or the loader pulls in, found through the
# import tables (works for x64 and ARM64 alike).
set +x
objdump=$(command -v llvm-objdump || command -v objdump)
declare -A seen
queue=("$out/deepwork.exe" "$out/$loaders/loaders/"*.dll)
while ((${#queue[@]})); do
    f=${queue[0]}
    queue=("${queue[@]:1}")
    for name in $("$objdump" -p "$f" | sed -n 's/^[[:space:]]*DLL Name: //p' | tr -d '\r'); do
        key=${name,,}
        [ -z "${seen[$key]:-}" ] || continue
        seen[$key]=1
        src="$prefix/bin/$name"
        [ -e "$src" ] || continue # part of Windows
        [ -e "$out/$name" ] || cp "$src" "$out/"
        queue+=("$src")
    done
done
echo "DLLs: $(ls "$out"/*.dll | wc -l)"
lap "DLLs"
set -x

# Icons: Adwaita for the interface, hicolor for the app's own icon.
mkdir -p "$out/share/icons/hicolor/scalable/apps"
cp -r "$prefix/share/icons/Adwaita" "$out/share/icons/"
cp "$prefix/share/icons/hicolor/index.theme" "$out/share/icons/hicolor/"
cp assets/icon.svg "$out/share/icons/hicolor/scalable/apps/io.github.ichbinstudent.DeepWork.svg"
gtk4-update-icon-cache -q -t -f "$out/share/icons/Adwaita" || echo "no icon cache"

# Licenses of everything bundled from MSYS2 (GTK and its libraries are
# LGPL: list exact versions and where their source is).
set +x
notices="$out/third-party/msys2"
mkdir -p "$notices"
{
    echo "The DeepWork app for Windows includes these packages from MSYS2"
    echo "(https://www.msys2.org), unmodified. The libraries are used as shared"
    echo "libraries (DLLs) and can be replaced with compatible builds."
    echo
    echo "Each package's source is at https://packages.msys2.org/package/<name>"
    echo "(exact versions are kept at https://repo.msys2.org/mingw/sources/)."
    echo "On request, the DeepWork project provides the corresponding source of"
    echo "these versions for at least three years after a release: ask at"
    echo "https://github.com/ichbinstudent/deepwork/issues"
    echo
} >"$notices/PACKAGES.txt"
# One pacman call each (pacman is slow, especially emulated on ARM).
owned=()
for f in "$out"/*.dll; do
    [ -e "$prefix/bin/$(basename "$f")" ] && owned+=("$prefix/bin/$(basename "$f")")
done
for f in "$out/$loaders/loaders/"*.dll; do
    owned+=("$prefix/$loaders/loaders/$(basename "$f")")
done
pkgs=$(
    {
        pacman -Qqo "${owned[@]}" 2>/dev/null || true
        echo "${MINGW_PACKAGE_PREFIX}-adwaita-icon-theme"
        echo "${MINGW_PACKAGE_PREFIX}-hicolor-icon-theme"
    } | sort -u
)
# shellcheck disable=SC2086 # one word per package
pacman -Qi $pkgs 2>/dev/null | awk '
    /^Name / { name = $3 }
    /^Version / { print name " " $3 }
    /^(URL|Licenses) / { print "    " $0 }
' >>"$notices/PACKAGES.txt"
for pkg in $pkgs; do
    name=${pkg#"${MINGW_PACKAGE_PREFIX}-"}
    if [ -d "$prefix/share/licenses/$name" ]; then
        cp -r "$prefix/share/licenses/$name" "$notices/$name"
    fi
done
echo "Notices for $(echo "$pkgs" | wc -l) MSYS2 packages"
lap "notices"
set -x

# GSettings schemas used by GTK (file and colour choosers).
mkdir -p "$out/share/glib-2.0/schemas"
cp "$prefix/share/glib-2.0/schemas/gschemas.compiled" "$out/share/glib-2.0/schemas/"

lap "icons and schemas"
echo "Bundled into $out: $(find "$out" -type f | wc -l) files, $(du -sh "$out" | cut -f1)"
