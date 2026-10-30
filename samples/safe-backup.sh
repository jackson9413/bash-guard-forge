#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <source_dir> <dest_dir>"
  exit 1
}

[ "$#" -eq 2 ] || usage

SRC_DIR="$1"
DEST_DIR="$2"

command -v rsync >/dev/null 2>&1 || { echo "rsync is required" >&2; exit 1; }

[ -d "$SRC_DIR" ] || { echo "source dir does not exist" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$DEST_DIR/backup-$STAMP"

mkdir -p "$TARGET"

cleanup() {
  rm -rf "$TARGET.tmp"
}
trap cleanup EXIT INT TERM

rsync -a --exclude '*.tmp' "$SRC_DIR/" "$TARGET/"
tar -czf "$TARGET.tar.gz" -C "$DEST_DIR" "$(basename "$TARGET")"
sha256sum "$TARGET.tar.gz" > "$TARGET.tar.gz.sha256"
find "$DEST_DIR" -name 'backup-*.tar.gz' -mtime +7 -delete

echo "backup written to $TARGET.tar.gz"
