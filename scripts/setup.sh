#!/bin/bash
# Creates a venv and installs flashfuzz (editable) with its requirements.
set -e
cd "$(dirname "$0")/.."

python=${1:-python3.12}
venv=${2:-.venv}

"$python" -m venv "$venv"
"$venv/bin/python" -m pip install -q -e .
