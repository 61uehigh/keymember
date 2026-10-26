#!/bin/sh
# Backs up keymember's data volume to a dated tarball, keeping recent ones.
#
#   deploy/backup.sh [backup directory]
#
# Safe to run from cron: it finds its own directory and uses no relative paths. The server is
# stopped for the few seconds the copy takes, so the database files are consistent.
set -eu

cd "$(dirname "$0")"

dest="${1:-${KEYMEMBER_BACKUP_DIR:-/var/backups/keymember}}"
keep_days="${KEYMEMBER_BACKUP_KEEP_DAYS:-30}"
compose="docker compose -f compose.yaml"

umask 077
mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"

container="$($compose ps -aq keymember)"

if [ -z "$container" ]; then
  echo "No keymember container here; start it with: $compose up -d" >&2
  exit 1
fi

name="keymember-$(date +%Y%m%d-%H%M%S).tar.gz"

$compose stop keymember
# Start the server again however the copy ends
trap '$compose start keymember >/dev/null' EXIT

docker run --rm --volumes-from "$container" -v "$dest:/backup" debian:bookworm-slim \
  tar czf "/backup/$name.partial" -C /data .
mv "$dest/$name.partial" "$dest/$name"

find "$dest" -name 'keymember-*.tar.gz' -mtime +"$keep_days" -exec rm -f {} +

echo "Backed up to $dest/$name"
