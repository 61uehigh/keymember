# Deploying on your own server with Docker

This guide runs keymember on a server your company already has (an on-premises server, a NAS or a cloud VM). Data is stored in PGlite (PostgreSQL) embedded in the server, so you don't need a separate database server. Caddy obtains and renews HTTPS certificates automatically.

If running your own server isn't practical, use the Cloud Run + Firestore setup in [cloud-run.md](cloud-run.md). Both use the same server code and the same Docker image.

## Prerequisites

- A Linux server with Docker and Docker Compose. For a few dozen people, 1 GB of memory is enough to run it, but since the image is built on that server, 2 GB or more is recommended during the build
- A domain pointing to this server (e.g. `vault.example.com`)
- Ports 80 and 443 on this server must be reachable from outside. Caddy uses them to obtain certificates

## 1. Get the code and configure

Clone the repository and, if there's a release tag, pin to that version. `main` is code under development and may include database changes.

```bash
git clone https://github.com/61uehigh/keymember.git && cd keymember
```

```bash
git checkout <release tag>
```

Create the config file.

```bash
cp deploy/.env.example deploy/.env
```

Fill in two values in `deploy/.env`. This file isn't committed to git.

- `KEYMEMBER_DOMAIN`: the domain (e.g. `vault.example.com`)
- `KEYMEMBER_SERVER_SECRET`: the output of the command below

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

**`deploy/.env` is not included in backups.** Keep it separately wherever your company stores secrets (an offline safe, for example). You'll need it when you rebuild the server.

## 2. Run

```bash
docker compose -f deploy/compose.yaml up -d --build
```

The first run takes a few minutes to build the image. The bootstrap token you enter when creating the organization is in the server log. This keeps someone else who learns the server URL first from taking over the organization.

```bash
docker compose -f deploy/compose.yaml logs keymember | grep "Bootstrap token"
```

To choose the token yourself, set `KEYMEMBER_BOOTSTRAP_TOKEN` in `deploy/.env`.

 If building on the server is impractical, replace `build: ..` in `deploy/compose.yaml` with a release image (`image: ghcr.io/61uehigh/keymember:<version>`) and just pull it. Caddy starts once keymember is healthy. When it's up, create your organization at `https://<domain>`, then invite members from the admin screen.

Check status and logs with the commands below. Logs are capped at 10 MB × 5 files per service.

```bash
docker compose -f deploy/compose.yaml ps
```

```bash
docker compose -f deploy/compose.yaml logs -f keymember
```

## 3. Backups

Data lives in the Docker volume `keymember-data`. Losing it means losing every vault, so back it up regularly. `deploy/backup.sh` stops the server for a few seconds, compresses the data, and starts it again. Backups older than 30 days are deleted (change this with `KEYMEMBER_BACKUP_KEEP_DAYS`).

```bash
deploy/backup.sh /var/backups/keymember
```

To run it every night, add the following line with `crontab -e`. Replace the repository path with the real location. The script finds its own location, so it works from cron.

```text
0 3 * * * /opt/keymember/deploy/backup.sh /var/backups/keymember >> /var/log/keymember-backup.log 2>&1
```

Copy the backup files to another location as well (another server or cloud storage). Items in the backup are end-to-end encrypted, but the backup contains account information and metadata, so restrict access to it. Backup files are created readable by the owner only.

## 4. Restore

`deploy/restore.sh` first checks that the backup file is intact, and saves the current data as `pre-restore-<timestamp>.tar.gz` next to the backup file before replacing it. If you restore the wrong file, you can undo it.

```bash
deploy/restore.sh /var/backups/keymember/keymember-20261026-030000.tar.gz
```

Test a restore once ahead of time.

### Moving to a new server or recovering from a lost server

1. Clone the repository on the new server and check out the same release tag you were using.
2. Put your saved `deploy/.env` in the same place.
3. Copy the backup file over and run `deploy/restore.sh <backup file>`. The script creates the container and volume if they don't exist.
4. Bring everything up, including Caddy, with `docker compose -f deploy/compose.yaml up -d`.
5. Point the domain's DNS to the new server.

## Company Google account login (optional)

Fill in `KEYMEMBER_PUBLIC_URL` (`https://<domain>`) and the `KEYMEMBER_OIDC_*` values in `deploy/.env`, then run `up -d` again. The OAuth client's redirect URI is `https://<domain>/api/auth/sso/callback`.

## Updating

Back up first, switch to the new release tag, and rebuild.

```bash
deploy/backup.sh /var/backups/keymember && git fetch --tags && git checkout <new release tag> && docker compose -f deploy/compose.yaml up -d --build
```

Database changes are applied automatically when the server starts, and they can't be rolled back. If something goes wrong after an update, go back to the previous tag and restore the backup taken just before the update.

## Operations

- **Health checks:** The container checks itself via `/api/health` every 30 seconds. Add an external uptime monitor on `https://<domain>/api/health` to find out about outages quickly.
- **Disk:** The data is small, but backups accumulate. Keep an eye on disk usage in the backup directory.
- **Shutdown:** On a shutdown signal, the server finishes in-flight requests and closes the database. A sudden power loss can lose the last writes, so if power is unreliable (on a NAS, for example), use a UPS or consider PostgreSQL below.
- **Rotating the server secret (`KEYMEMBER_SERVER_SECRET`):** This value encrypts the tokens used for company account login inside the server and is used to generate decoy responses for nonexistent emails. It has nothing to do with vault data. If it leaks, set a new value and restart with `up -d`. People who logged in with their company account will need to log in again.

## Using PostgreSQL

If you already run PostgreSQL, set `DATABASE_URL` in `deploy/.env`. When set, it takes precedence over the PGlite path configured in the image. Back up using that database's own method (`pg_dump`, etc.) and don't use `deploy/backup.sh`.
