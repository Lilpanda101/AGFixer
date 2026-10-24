#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
command -v python3 >/dev/null || { echo 'Нужен Python 3.10 или новее'; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else "Нужен Python 3.10 или новее")'
exec python3 agfixer_linux.py "$@"
