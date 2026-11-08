#!/usr/bin/env bash
set -euo pipefail

version="$(sed -n 's/^channel = "\([0-9][0-9.]*\)"$/\1/p' rust-toolchain.toml)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "rust-toolchain.toml must pin one exact Rust version" >&2
  exit 1
fi

printf '%s\n' "$version"
