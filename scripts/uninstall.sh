#!/bin/sh

set -eu

INSTALL_ROOT="${INSTALL_ROOT:-${HOME}/.local/share/unifiwifioptimizer}"
BIN_DIR="${BIN_DIR:-${HOME}/.local/bin}"
CMD_NAME="${CMD_NAME:-unifiwifioptimizer}"
UNINSTALL_NAME="${UNINSTALL_NAME:-unifiwifioptimizer-uninstall}"

case "$INSTALL_ROOT" in
  ""|"/"|"$HOME"|".")
    printf 'ERROR: Refusing unsafe INSTALL_ROOT: %s\n' "$INSTALL_ROOT" >&2
    exit 1
    ;;
esac

rm -f "$BIN_DIR/$CMD_NAME" "$BIN_DIR/$UNINSTALL_NAME"
rm -rf "$INSTALL_ROOT"

printf 'Removed %s\n' "$CMD_NAME"
printf '  Deleted: %s\n' "$INSTALL_ROOT"
printf '  Removed launchers from: %s\n' "$BIN_DIR"
