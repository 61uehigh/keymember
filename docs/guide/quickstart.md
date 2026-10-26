# Try it locally

Run the server and web vault on your own computer, then use the CLI to create an organization, invite a teammate and share. To deploy for your company, see [Cloud Run + Firestore](../deploy/cloud-run.md) or [your own server](../deploy/self-hosted.md).

## Start the server

```bash
pnpm install && pnpm build   # builds the packages and the web app (apps/web/dist) together
```

Start the server and web vault together in local development mode, using PGlite.

```bash
KEYMEMBER_WEB_DIR=apps/web/dist KEYMEMBER_PGLITE_DIR=./.data KEYMEMBER_SERVER_SECRET=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=') node apps/server/dist/main.js
```

You can create an organization at http://127.0.0.1:8080. To create it, you need the bootstrap token the server prints to its log on startup (`Bootstrap token for creating it: …`). This keeps someone else who learns the server URL first from taking over the organization. To choose the token yourself, set `KEYMEMBER_BOOTSTRAP_TOKEN`.

## Try the CLI

Run these in another terminal.

```bash
alias keymember="node $PWD/apps/cli/dist/main.js"
keymember init http://127.0.0.1:8080
KEYMEMBER_BOOTSTRAP_TOKEN=<bootstrap token from the server log> keymember bootstrap --org Example --email me@example.com --name Me
keymember vault create Personal
keymember item add Personal --title GitHub --url https://github.com --username me --generate
keymember item get GitHub --field password
keymember run --env GITHUB_TOKEN=GitHub.password -- ./deploy.sh
```

## Invite teammates

In the web app, go to **Admin → Members**, enter an email address, click **Create invite**, then **Send by email** or **Send via Slack**.

1. The admin creates an invite link with `keymember invite <email>` and sends it by email or Slack. The keymember server doesn't send email.
2. The teammate opens the link in a browser (or runs `keymember signup --link '<link>' --name <name>`) and signs up by choosing just a name and password.
3. The next time the admin's app opens (web, extension, desktop, or CLI `members`), it certifies the teammate's key automatically. There's no need to compare fingerprints. If the teammate signed up by entering only a token without a link, certify them by comparing fingerprints with `keymember certify <email> --fingerprint ...`.
4. The admin shares a vault with `keymember vault share`.

## Share with a group

To share with several people at once, use a group. Anyone who joins the group later can open the vaults shared with it right away.

```bash
keymember group create DevTeam --member bob@example.com --member carol@example.com
keymember vault create Deploy --group DevTeam:edit
keymember group remove DevTeam carol@example.com   # rotates the group key
keymember vault rotate Deploy                      # to also replace the vault keys the removed person saw
```

## Share links

Send a single item to someone outside the vault (a contractor, or a new hire before their start date) as a link with an expiry time and a view limit. The key lives only in the link, so even the server can't see the contents, and you can set a separate passphrase for opening it.

```bash
keymember item share GitHub --hours 24 --views 1 --passphrase
```
