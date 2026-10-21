#!/usr/bin/env python3
"""Validate CLI -> clash-lib feature forwarding without compiling dependencies.

Run from any cwd: python3 ci/check-feature-forwarding.py
Uses Cargo metadata rather than trying to parse Cargo.toml by hand.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
    command = [
        cargo, "metadata", "--no-deps", "--offline", "--format-version", "1",
    ]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    packages = {p["name"]: p for p in json.loads(result.stdout)["packages"]}
    cli = packages["clash-rs"]["features"]
    lib = packages["clash-lib"]["features"]

    # Each explicitly forwarded CLI feature should enable its equivalent
    # clash-lib feature. Feature aliases (standard, plus, perf) are deliberately
    # aggregations and are checked for valid feature references below.
    errors = []
    for feature, deps in sorted(cli.items()):
        if feature != "default" and feature in lib and f"clash-lib/{feature}" not in deps:
            errors.append(f"CLI feature {feature!r} does not forward clash-lib/{feature}")
        for dep in deps:
            if dep.startswith("clash-lib/"):
                name = dep.removeprefix("clash-lib/").split("?", 1)[0]
                if name not in lib:
                    errors.append(f"CLI feature {feature!r} targets absent clash-lib/{name}")
            elif not dep.startswith("dep:") and "/" not in dep:
                if dep not in cli:
                    errors.append(f"CLI feature {feature!r} references missing CLI feature {dep!r}")

    # Some historical feature names intentionally remain accepted while the
    # respective upstream capabilities are absent; make that visible, but
    # never claim they provide Tor or jemalloc functionality.
    if not cli.get("onion"):
        print("LIMITATION: CLI 'onion' is an empty compatibility placeholder; Tor is not implemented")
    if "jemallocator" not in cli and "perf" in cli:
        print("LIMITATION: CLI 'perf' is an aggregate alias, not upstream's jemallocator build")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"PASS: {len(cli)} CLI feature definitions; {len(lib)} core feature definitions checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
