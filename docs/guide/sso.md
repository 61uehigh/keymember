# Company Google account (SSO) and offboarding

## SSO setup

You can require members to verify their company Google account at login, in addition to their password and Secret Key. When you suspend an account in Google Workspace, its keymember logins on every device are cut off within 15 minutes. Unlocking a vault still uses only the password and Secret Key.

1. In the Google Cloud Console, set the OAuth consent screen to **Internal** and create a "Web application" OAuth client. The authorized redirect URI is `<server URL>/api/auth/sso/callback`.
2. Start the server with the following environment variables. The client secret is a secret, so don't commit it to the repository; keep it in your deployment environment's secret store.
   - `KEYMEMBER_OIDC_ISSUER=https://accounts.google.com`
   - `KEYMEMBER_OIDC_CLIENT_ID`, `KEYMEMBER_OIDC_CLIENT_SECRET`
   - `KEYMEMBER_OIDC_HOSTED_DOMAIN=example.com` (allow only accounts in this domain)
   - `KEYMEMBER_PUBLIC_URL=https://keymember.example.com` (the server URL browsers connect to)
3. In the web app, go to **Admin → Policies**, click **Verify my login with my company account**, then turn on **Require company account verification (SSO)**. From the CLI, run `keymember policy --require-sso on`. As soon as it's on, every login that didn't go through SSO is cut off, and members verify their Google account when they log in again.

## Offboarding

Use **Offboard** in the web app's **Admin → Members**, or `keymember member offboard <email>`. This suspends the account and immediately rotates the keys of the groups the person belonged to and of the vaults managed by the admin doing the offboarding. The remaining vaults are marked **Key rotation needed**, and the results screen lists each vault's managers.
