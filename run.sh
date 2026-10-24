#!/usr/bin/env bash
# AGFixer Linux Root Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/linux/run.sh" "$@"
