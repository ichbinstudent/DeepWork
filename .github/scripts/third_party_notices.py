#!/usr/bin/env python3
"""Write the notices for every Rust crate DeepWork is built from: name,
version, license and the license texts the crate ships with.

    python3 .github/scripts/third_party_notices.py THIRD-PARTY-NOTICES.txt

Covers the crates of every platform (downloading them if needed), so one
file serves all packages.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|notice|unlicense)([-_.].*)?$", re.I)


def main() -> None:
    # The crates of every platform, not only the ones this build used.
    subprocess.run(["cargo", "fetch", "--locked"], check=True)
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--locked"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    workspace = set(meta["workspace_members"])
    used = {node["id"] for node in meta["resolve"]["nodes"]} - workspace
    packages = sorted(
        (p for p in meta["packages"] if p["id"] in used),
        key=lambda p: (p["name"], p["version"]),
    )

    out = []
    out.append("DeepWork includes the following Rust crates. Their licenses follow.\n")
    out.append("(The Windows packages also include GTK and other libraries from MSYS2;\n")
    out.append("see third-party/msys2/PACKAGES.txt.)\n\n")
    for p in packages:
        out.append(f"  {p['name']} {p['version']}  {p.get('license') or 'see below'}\n")
    out.append("\n")

    for p in packages:
        out.append("=" * 78 + "\n")
        out.append(f"{p['name']} {p['version']}\n")
        out.append(f"License: {p.get('license') or p.get('license_file') or 'unknown'}\n")
        if p.get("repository"):
            out.append(f"Source: {p['repository']}\n")
        authors = ", ".join(p.get("authors") or [])
        if authors:
            out.append(f"Authors: {authors}\n")
        root = Path(p["manifest_path"]).parent
        files = sorted(f for f in root.iterdir() if f.is_file() and LICENSE_FILE.match(f.name))
        if not files:
            out.append(
                "\n(The crate ships no license file; the standard text of the license "
                "named above applies.)\n\n"
            )
        for f in files:
            out.append(f"\n--- {f.name} ---\n\n")
            out.append(f.read_text(encoding="utf-8", errors="replace").rstrip() + "\n")
        out.append("\n")
    Path(sys.argv[1]).write_text("".join(out), encoding="utf-8")


if __name__ == "__main__":
    main()
