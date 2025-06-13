#!/usr/bin/env bash
set -e

# Install/upgrade gdb_plus from mounted volume
pip3 install --upgrade /home/root/gdb_plus
chmod +x /home/root/gdb_plus/tests/*

# Execute any passed-in command (e.g., tmux)
exec "$@"