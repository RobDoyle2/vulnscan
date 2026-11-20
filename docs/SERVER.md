# Running VulnScan on an internal Linux server

This guide is for the person installing VulnScan for a team. The result is an internal web address, for example `https://vulnscan.yourcompany.internal`. Staff sign in with their Microsoft Entra ID work account and see the same screens as the desktop app.

```
 staff browser ──HTTPS──▶ signin (oauth2-proxy) ──▶ vulnscan container ──HTTPS──▶ 9 public feeds
 (PC / phone on VPN)       Entra ID sign-in          not reachable directly       (outbound only)
```

* **signin** is [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/), a widely used open-source sign-in gateway.
  * It sends people to Microsoft sign-in, checks they are in the allowed Entra group, and only then passes requests on.
  * It tells VulnScan who the person is, in the `X-Forwarded-Email` and `X-Forwarded-Groups` headers. It removes any such headers a browser tries to send itself.
* **vulnscan** has no published port. Only the gateway can reach it, and it refuses any request without a signed-in identity.
* **Roles:**
  * Viewers (everyone allowed to sign in) can see, filter and export results.
  * Admins (an Entra group or named people) can also start a scan, change sources and test them.
  * Scans also run automatically every 6 hours.

## What you need

* A Linux server with Docker Engine and the Docker Compose plugin.
* A DNS name for it, for example `vulnscan.yourcompany.internal`, and a TLS certificate for that name from your internal certificate authority.
* Outbound HTTPS from the server to the addresses listed in [SECURITY.md](SECURITY.md#outbound-connections), either directly or through your proxy.
* Someone who can create an app registration in Microsoft Entra ID.

## 1. Entra ID app registration (about 10 minutes)

In the **Microsoft Entra admin center**:

1. **App registrations → New registration**
   * Name: `VulnScan`.
   * Supported account types: *Accounts in this organizational directory only*.
   * Redirect URI: platform **Web**, `https://vulnscan.yourcompany.internal/oauth2/callback`.
   * Note the **Application (client) ID** and the **Directory (tenant) ID**.
2. **Certificates & secrets → New client secret.** Copy the value now; it is shown only once. Note its expiry date, because sign-in stops when it expires.
3. **Token configuration → Add groups claim.**
   * Choose **Groups assigned to the application**. This avoids the 200-group limit for people in many groups.
   * Under ID token, choose **Group ID**.
4. Create two security groups, or reuse existing ones, and note their **Object IDs**:
   * `VulnScan users`: everyone who may open VulnScan.
   * `VulnScan admins`: people who may start scans and change sources. Add them to `VulnScan users` as well.
5. **Enterprise applications → VulnScan:**
   * **Properties → Assignment required? = Yes.**
   * **Users and groups → Add:** both groups.

## 2. Get the files onto the server

```bash
git clone https://github.com/RobDoyle2/vulnscan.git   # or your internal copy
cd vulnscan/deploy
cp vulnscan.env.example vulnscan.env
cp signin.env.example signin.env
mkdir -p tls secrets
```

## 3. Fill in the settings

**`signin.env`:**

* `OAUTH2_PROXY_OIDC_ISSUER_URL`: replace `YOUR-TENANT-ID`.
* `OAUTH2_PROXY_CLIENT_ID` and `OAUTH2_PROXY_CLIENT_SECRET`: from step 1.
* `OAUTH2_PROXY_REDIRECT_URL`: your address, followed by `/oauth2/callback`.
* `OAUTH2_PROXY_ALLOWED_GROUPS`: the Object ID of `VulnScan users`.
* `OAUTH2_PROXY_COOKIE_SECRET`: generate with `openssl rand -base64 32 | tr -- '+/' '-_'`.

**`vulnscan.env`:**

* `VULNSCAN_ADMIN_GROUPS`: the Object ID of `VulnScan admins`. Alternatively, set `VULNSCAN_ADMINS` to a comma-separated list of sign-in names.
* `VULNSCAN_SCAN_EVERY_HOURS`: how often to collect. The default is 6.
* **Corporate proxy**, if the server must use one:
  * `HTTPS_PROXY`, and `NO_PROXY=localhost,127.0.0.1,vulnscan`.
  * If that proxy inspects HTTPS traffic, put the company root certificate (PEM) in `deploy/certs/company-root.pem`.
  * Uncomment the `certs` line in `docker-compose.yml`, and set `VULNSCAN_EXTRA_CA_FILE=/certs/company-root.pem`. The public certificates are still trusted as well.

**TLS:** put the server certificate and key in `tls/server.crt` and `tls/server.key`. They must be readable by user ID 65532, the gateway's user: run `chmod 644 tls/server.crt` and `chmod 640 tls/server.key`, then `chgrp 65532 tls/server.key`.

**NVD API key** (optional, makes scans much faster): put it on one line in `secrets/nvd_api_key`. A GitHub token isn't needed on the server: without one, VulnScan reads a limited number of GitHub advisories per run and continues on the next run.

## 4. Build and start

```bash
docker compose up -d --build
docker compose logs -f vulnscan     # watch the first scan: an ok / FAIL line per source
```

**If the build fails with "certificate verify failed"**, your network inspects HTTPS. Build with the company root certificate:

```bash
docker build --secret id=company_ca,src=certs/company-root.pem -t vulnscan:1.0.0 ..
docker compose up -d
```

The certificate is used only during the build and isn't kept in the image.

Open `https://vulnscan.yourcompany.internal`. You are sent to Microsoft sign-in, then to VulnScan. The header shows who you are signed in as, and *(administrator)* for admins.

## Day to day

| Task | How |
|---|---|
| See scan results per source | `docker compose logs vulnscan`. Each scan writes one `ok` or `FAIL` line per source, with the reason. |
| Health check for monitoring | `GET /healthz` on the vulnscan container (no sign-in needed; the container's own health check uses it). |
| Back up | The Docker volume `vulnscan-data` (`vulns.db` and `settings.json`). Everything in it can be rebuilt by scanning again. |
| Update | `git pull`, then `docker compose up -d --build`. |
| Rotate the client secret | Create a new one in Entra, update `signin.env`, then `docker compose up -d`. |
| Turn sign-in off for a test | `VULNSCAN_AUTH=none`. **Testing only:** anyone who can reach the port becomes an admin. |

## Settings reference (`vulnscan.env`)

| Variable | Default | Meaning |
|---|---|---|
| `VULNSCAN_ADMIN_GROUPS` | (none) | Entra group Object IDs whose members are admins |
| `VULNSCAN_ADMINS` | (none) | Sign-in names that are admins |
| `VULNSCAN_SCAN_EVERY_HOURS` | `6` | Automatic scan interval |
| `VULNSCAN_AUTH` | `header` | `header` = trust only the gateway's identity headers; `none` = testing only |
| `NVD_API_KEY` / `NVD_API_KEY_FILE` | (none) | NVD key, or a file containing it |
| `GITHUB_TOKEN` / `GITHUB_TOKEN_FILE` | (none) | Optional GitHub token, needing no permissions |
| `HTTPS_PROXY`, `NO_PROXY` | (none) | Outbound proxy |
| `VULNSCAN_EXTRA_CA_FILE` | (none) | Extra root certificate(s) to trust, PEM |
| `VULNSCAN_PORT`, `VULNSCAN_BIND` | `8080`, `0.0.0.0` | Where the container listens |
