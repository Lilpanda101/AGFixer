#!/usr/bin/env bash
# AGFixer Linux Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/agfixer_linux.py" "$@"
