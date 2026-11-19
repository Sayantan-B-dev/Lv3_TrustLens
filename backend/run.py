#!/usr/bin/env python3
"""Start the TrustLens backend, or run a command with backend/.venv.

Default (no arguments) starts the API with reload on port 8000:
    python backend/run.py

Other examples:
    python backend/run.py -m pytest
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent


def venv_python() -> str:
    candidate = BACKEND_DIR / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return str(candidate if candidate.exists() else Path(sys.executable))


def main() -> int:
    if len(sys.argv) > 1:
        command = [venv_python(), *sys.argv[1:]]
    else:
        command = [
            venv_python(),
            "-m",
            "uvicorn",
            "trustlens.main:app",
            "--reload",
            "--port",
            "8000",
        ]
    return subprocess.call(command, cwd=str(BACKEND_DIR))


if __name__ == "__main__":
    raise SystemExit(main())
