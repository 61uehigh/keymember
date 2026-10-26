# Deploying with Cloud Run + Firestore

This guide runs keymember in a single company Google Cloud project. Cloud Run starts the server only when requests come in, and data is stored in Firestore. There are no servers or databases for you to manage.

If you have your own server, you can also choose the Docker setup in [self-hosted.md](self-hosted.md). Both use the same server code and the same Docker image.

## Cost

A team-sized deployment (a few dozen people) mostly fits within the free tier. Cloud Run does, however, require a billing account linked to the project.

| Item | Free tier (summary) | keymember usage |
|---|---|---|
| Firestore | 1 GiB storage, 50,000 reads and 20,000 writes per day | Tens of MB of storage. Sync reads only items that changed |
| Cloud Run | 2 million requests per month plus some CPU time | Scales to zero when there are no requests |
| Cloud Build, Artifact Registry | Build minutes and 0.5 GB of image storage | Each deploy adds an image. Set up the cleanup policy in step 7 |
| Firestore scheduled backups | No free tier | A small charge based on backup size |

Limits and prices can change, so check [Firestore pricing](https://cloud.google.com/firestore/pricing) and [Cloud Run pricing](https://cloud.google.com/run/pricing). The Firestore free tier applies only to the project's `(default)` database, so that is the one used below. To avoid surprise charges, set up a [budget alert](https://cloud.google.com/billing/docs/how-to/budgets).

## Prerequisites

- A Google Cloud project and a billing account
- The [gcloud CLI](https://cloud.google.com/sdk/docs/install), logged in (`gcloud auth login`)
- A local clone of this repository

In the commands below, replace `PROJECT_ID` with your project ID and `asia-northeast3` (Seoul) with the region you want.

```bash
gcloud config set project PROJECT_ID
```

## 1. Enable the APIs

```bash
gcloud services enable run.googleapis.com firestore.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
```

## 2. Create the Firestore database

Create the `(default)` database in Native mode. You can't change the region later.

```bash
gcloud firestore databases create --location=asia-northeast3
```

keymember only uses equality (`==`) and single-field range queries, so you don't need any composite indexes.

The server deletes expired login challenges, company account login tickets and sessions every hour. To have them deleted even while the server is scaled to zero because nobody is using it, turn on Firestore TTL (optional).

```bash
gcloud firestore fields ttls update expiresAt --collection-group=loginChallenges --enable-ttl
```

```bash
gcloud firestore fields ttls update expiresAt --collection-group=ssoTickets --enable-ttl
```

```bash
gcloud firestore fields ttls update refreshExpiresAt --collection-group=sessions --enable-ttl
```

## 3. Create the server secret

Store `KEYMEMBER_SERVER_SECRET` in Secret Manager. The value is saved directly without being shown on screen. Once set, don't change it.

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | gcloud secrets create keymember-server-secret --data-file=-
```

## 4. Service account and permissions

Create a dedicated service account for the server and allow only Firestore read/write and secret access.

```bash
gcloud iam service-accounts create keymember --display-name="keymember server"
```

```bash
gcloud projects add-iam-policy-binding PROJECT_ID --member="serviceAccount:keymember@PROJECT_ID.iam.gserviceaccount.com" --role="roles/datastore.user"
```

```bash
gcloud secrets add-iam-policy-binding keymember-server-secret --member="serviceAccount:keymember@PROJECT_ID.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
```

## 5. Deploy

Run this from the repository folder. Cloud Build builds an image from the repository's `Dockerfile` and deploys it.

```bash
gcloud run deploy keymember --source . --region asia-northeast3 --service-account keymember@PROJECT_ID.iam.gserviceaccount.com --allow-unauthenticated --max-instances 1 --set-env-vars KEYMEMBER_STORE=firestore,KEYMEMBER_TRUST_PROXY=1 --set-secrets KEYMEMBER_SERVER_SECRET=keymember-server-secret:latest
```

- `--allow-unauthenticated`: keymember handles login itself, so turn off Cloud Run's front-end authentication.
- `--max-instances 1`: The failed-login rate limit is kept in server memory, so run a single instance. Each additional instance loosens the attempt limit accordingly. The count starts over when the instance restarts or you deploy a new version.
- `KEYMEMBER_TRUST_PROXY=1`: Records the real client IP that Cloud Run adds in the audit log.

When the deploy finishes, you get a URL like `https://keymember-….run.app`. Cloud Run manages the HTTPS certificate. Open that URL to create your organization, then invite members from the admin screen.

Creating the organization requires a bootstrap token. This keeps someone else who learns the server URL first from taking over the organization. The server prints it to the log on startup, so find it with the command below. The token changes whenever the instance restarts, so use the most recent line.

```bash
gcloud run services logs read keymember --region asia-northeast3 --limit 200 | grep "Bootstrap token"
```

The instance shuts down after a period without requests, so the first request after that can take a few seconds. To always respond immediately, add `--min-instances 1`, at extra cost.

### If the deploy fails

- **"Cannot add allUsers" error:** Google Workspace organizations often have an org policy that blocks public access (`iam.allowedPolicyMemberDomains`). Use `--no-invoker-iam-check` instead of `--allow-unauthenticated` to turn off only the auth check without granting public access. If it's still blocked, ask your organization admin for an exception for this project.
- **Build permission error:** In recent projects, `--source` builds run as the Compute Engine default service account, which may lack permissions. Ask your organization admin to grant that account `roles/run.builder`.

### Using a company domain

You can keep the `run.app` URL, but members' extensions and apps remember the address, so settle on it **before you invite members**. If you change it later, every device has to re-enter the server URL, and you also have to change the redirect URI for company account login. To use a company domain (e.g. `vault.example.com`), use [Cloud Run domain mapping](https://cloud.google.com/run/docs/mapping-custom-domains) or an external Application Load Balancer. Domain mapping is only available in some regions.

## 6. Backups

Turn on Firestore scheduled backups. The following backs up daily and keeps each backup for 7 days.

```bash
gcloud firestore backups schedules create --database="(default)" --recurrence=daily --retention=7d
```

To recover, pick a backup from the list and restore it to a new database.

```bash
gcloud firestore backups list --location=asia-northeast3
```

```bash
gcloud firestore databases restore --source-backup=projects/PROJECT_ID/locations/asia-northeast3/backups/BACKUP_ID --destination-database=keymember-restored
```

When the restore finishes, update the service with `--update-env-vars KEYMEMBER_FIRESTORE_DATABASE=keymember-restored`. The free tier applies only to `(default)`, so the restored database may incur a small charge. For details, see the [Firestore backup docs](https://cloud.google.com/firestore/docs/backups).

## 7. Clean up old images

`--source` deploys accumulate images in the `cloud-run-source-deploy` repository. Set a cleanup policy that keeps only the 5 most recent.

```bash
printf '%s' '[{"name":"keep-recent","action":{"type":"Keep"},"mostRecentVersions":{"keepCount":5}},{"name":"delete-rest","action":{"type":"Delete"},"condition":{"tagState":"ANY"}}]' > cleanup-policy.json
```

```bash
gcloud artifacts repositories set-cleanup-policies cloud-run-source-deploy --location=asia-northeast3 --policy=cleanup-policy.json
```

## Company Google account login (optional)

To require login with a Google Workspace account, create an OAuth client. The redirect URI is `<service URL>/api/auth/sso/callback`.

First, put the client secret in Secret Manager and give the service account read access. Replace `CLIENT_SECRET` with the real value.

```bash
printf '%s' 'CLIENT_SECRET' | gcloud secrets create keymember-oidc-secret --data-file=-
```

```bash
gcloud secrets add-iam-policy-binding keymember-oidc-secret --member="serviceAccount:keymember@PROJECT_ID.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor"
```

Then set the values on the service.

```bash
gcloud run services update keymember --region asia-northeast3 --update-env-vars KEYMEMBER_PUBLIC_URL=https://SERVICE_URL,KEYMEMBER_OIDC_ISSUER=https://accounts.google.com,KEYMEMBER_OIDC_CLIENT_ID=CLIENT_ID,KEYMEMBER_OIDC_HOSTED_DOMAIN=COMPANY_DOMAIN --update-secrets KEYMEMBER_OIDC_CLIENT_SECRET=keymember-oidc-secret:latest
```

## Updating

Check out the new release tag, then run the `gcloud run deploy` command from step 5 again. `main` is code under development, so use a tag. Firestore has no schema migration step. If something goes wrong, you can send traffic back to the previous revision in the Cloud Run console.

## Operations

- **Logs:** Requests and errors appear in the Cloud Run service logs in Cloud Logging.
- **Health checks:** Set up a Cloud Monitoring uptime check on `https://SERVICE_URL/api/health` to find out about outages quickly.
- **Rotating the server secret:** `KEYMEMBER_SERVER_SECRET` encrypts company account login tokens inside the server and is used to generate decoy responses for nonexistent emails. It has nothing to do with vault data. If it leaks, add a new value with `gcloud secrets versions add keymember-server-secret --data-file=-` and deploy a new revision. People who logged in with their company account will need to log in again.

## Environment variables

| Variable | Value |
|---|---|
| `KEYMEMBER_STORE` | `firestore` |
| `KEYMEMBER_SERVER_SECRET` | Injected from Secret Manager |
| `KEYMEMBER_TRUST_PROXY` | `1` |
| `KEYMEMBER_FIRESTORE_DATABASE` | Only when not `(default)` |
| `KEYMEMBER_PUBLIC_URL`, `KEYMEMBER_OIDC_*` | Only when using company account login |

`PORT` is set by Cloud Run, and the web app location (`KEYMEMBER_WEB_DIR`) by the image.
