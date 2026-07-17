#!/usr/bin/env bash
# Double-clickable build launcher for macOS — no Terminal knowledge needed.
# Finder runs .command files in a new Terminal window automatically.
cd "$(dirname "$0")"
./build_macos.sh
echo
read -n 1 -s -r -p "Press any key to close this window…"
