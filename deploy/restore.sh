#!/bin/sh
# Restores a backup made by backup.sh, on this server or a new one.
#
#   deploy/restore.sh <backup file>
#
# Checks the backup before touching anything, and saves the current data next to it as
# pre-restore-<time>.tar.gz first, so a wrong file can be undone.
set -eu

cd "$(dirname "$0")"

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <backup file>" >&2
  exit 1
fi

file="$1"

if [ ! -s "$file" ] || ! tar tzf "$file" >/dev/null 2>&1; then
  echo "$file is missing, empty or not a readable tarball; nothing was changed" >&2
  exit 1
fi

if ! tar tzf "$file" | grep -q 'PG_VERSION$'; then
  echo "$file does not look like a keymember backup; nothing was changed" >&2
  exit 1
fi

dir="$(cd "$(dirname "$file")" && pwd)"
name="$(basename "$file")"
compose="docker compose -f compose.yaml"

# On a new server the container and its volume do not exist yet
$compose create keymember
container="$($compose ps -aq keymember)"

$compose stop keymember

safety="pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz"

docker run --rm --volumes-from "$container" -v "$dir:/backup" debian:bookworm-slim \
  tar czf "/backup/$safety" -C /data .
docker run --rm --volumes-from "$container" -v "$dir:/backup:ro" debian:bookworm-slim \
  sh -c "find /data -mindepth 1 -delete && tar xzf '/backup/$name' -C /data && chown -R 1000:1000 /data"

$compose start keymember

echo "Restored $file. The data it replaced is in $dir/$safety"
