#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
python3 tools/anon_scan.py
