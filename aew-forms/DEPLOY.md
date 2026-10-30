# Going live: sign-in, Turnstile, cards

Never paste a key or secret into a chat. Paste them only into the Cloudflare or Google screens named below.

## 1. Turnstile (bot check, free)
1. Cloudflare dashboard > Turnstile > Add widget.
2. Name: `AEW site`. Hostnames: `aiemployeeworkflow.com` and `www.aiemployeeworkflow.com`. Widget mode: Managed.
3. Keep the page open. You need the Site key and the Secret key in step 4.

## 2. Google sign-in
1. console.cloud.google.com > APIs & Services > OAuth consent screen. Choose External. App name `AI Employee Workflow`, support email `aew.workflow@gmail.com`. Add the privacy link `https://aiemployeeworkflow.com/privacy`. Don't add extra scopes (the default openid, email and profile are all we use). Publish the app.
2. Credentials > Create credentials > OAuth client ID > Web application.
3. Authorized redirect URI: `https://aiemployeeworkflow.com/auth/google/callback`
4. Keep the page open. You need the Client ID and the Client secret in step 4.

## 3. Database (D1)
Cloudflare > Storage & databases > D1 > aew-signups > Console. Paste everything in `migration-2026-10-30.sql` and run it once.

## 4. aew-forms settings
Workers & Pages > aew-forms > Settings > Variables and Secrets > Add. Pick type **Secret** for all of these except the last one:

| Name | What to paste |
|---|---|
| `SESSION_SECRET` | A new random password, at least 32 characters (use your password manager's generator, 48+ characters) |
| `GOOGLE_CLIENT_ID` | Google Client ID |
| `GOOGLE_CLIENT_SECRET` | Google Client secret |
| `TURNSTILE_SECRET` | Turnstile Secret key |
| `TURNSTILE_SITEKEY` (type **Text**) | Turnstile Site key (this one is public) |

## 5. Deploy aew-forms, then merge the website (do these back to back)
1. A copy of the code that's live now is in `worker.deployed-2026-10-27.js`.
2. Workers & Pages > aew-forms > Edit code. Select everything in `worker.js` there, paste in this folder's `worker.js`, click Deploy.
3. Right away, merge the website pull request. Between these two steps the live site can't take tasks or sign-ups.
4. Check the aew-website build log (Workers & Pages > aew-website > Deployments). The deploy command should be `npx wrangler deploy`.

**Roll back:** aew-forms > Deployments > pick the Oct 27 version > Rollback. For the site, revert the merge on GitHub.

## LinkedIn (later)
LinkedIn needs an app tied to an AEW LinkedIn Company Page.
1. Create a Company Page for AEW on LinkedIn, if you don't have one yet.
2. linkedin.com/developers > Create app. Link it to that page and add the logo and the privacy link. The page admin approves the link (Settings tab > Verify).
3. Products tab > request **Sign In with LinkedIn using OpenID Connect**.
4. Auth tab > Authorized redirect URL: `https://aiemployeeworkflow.com/auth/linkedin/callback`.
5. In aew-forms > Variables and Secrets, add the Secrets `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET`.
The LinkedIn button switches from "Coming soon" to live on its own. The website doesn't need any change.
