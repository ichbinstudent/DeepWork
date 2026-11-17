#!/usr/bin/env bash
# Collect the GTK app and everything it needs from MSYS2 (UCRT64) into DIR:
# DLLs, the SVG image loader, icons and GSettings schemas. GTK finds share/
# and lib/ next to its DLLs, so the folder works wherever it is copied.
#   usage (in an MSYS2 UCRT64 shell, after cargo build --release -p deepwork):
#   bundle-windows-app.sh DIR
set -euo pipefail
out=$1
prefix=${MINGW_PREFIX:?run this in an MSYS2 shell}
mkdir -p "$out"
cp "${CARGO_TARGET_DIR:-target}/release/deepwork.exe" windows/deepwork.ico "$out/"

# The SVG loader (icons are SVG) and a template of its loader list; the app
# fills in the absolute path at start-up.
loaders=lib/gdk-pixbuf-2.0/2.10.0
mkdir -p "$out/$loaders/loaders"
cp "$prefix/$loaders/loaders/"*svg*.dll "$out/$loaders/loaders/"
(cd "$out/$loaders/loaders" && gdk-pixbuf-query-loaders ./*.dll) |
    sed -E 's#^"[^"]*[\\/]+(libpixbufloader[^"]*)"#"@LOADERS_DIR@/\1"#' >"$out/$loaders/loaders.cache.in"
grep -q '@LOADERS_DIR@' "$out/$loaders/loaders.cache.in"

# Every MSYS2 DLL that the app or the loader pulls in.
for f in "$out/deepwork.exe" "$out/$loaders/loaders/"*.dll; do
    ldd "$f" | awk '{print $3}' | grep -i "^$prefix/bin/" || true
done | sort -u | while read -r dll; do
    cp -n "$dll" "$out/"
done

# Icons: Adwaita for the interface, hicolor for the app's own icon.
mkdir -p "$out/share/icons/hicolor/scalable/apps"
cp -r "$prefix/share/icons/Adwaita" "$out/share/icons/"
cp "$prefix/share/icons/hicolor/index.theme" "$out/share/icons/hicolor/"
cp assets/icon.svg "$out/share/icons/hicolor/scalable/apps/io.github.ichbinstudent.DeepWork.svg"
gtk4-update-icon-cache -q -t -f "$out/share/icons/Adwaita" || true

# GSettings schemas used by GTK (file and colour choosers).
mkdir -p "$out/share/glib-2.0/schemas"
cp "$prefix/share/glib-2.0/schemas/gschemas.compiled" "$out/share/glib-2.0/schemas/"

echo "Bundled into $out: $(find "$out" -type f | wc -l) files, $(du -sh "$out" | cut -f1)"
