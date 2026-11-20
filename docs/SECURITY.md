# VulnScan: data flow and security

A summary for a security review of the **internal server** deployment ([SERVER.md](SERVER.md)).

## What it does

VulnScan downloads **public** vulnerability information (CVE lists and vendor advisories) from 9 public sources. It stores the information in a local database and shows it, ranked, to signed-in staff. It holds **no company data**: no inventory, no hostnames, no user data beyond the sign-in name it shows on screen and writes to its log.

## Data flow

```
 staff browser ──HTTPS──▶ signin gateway ──HTTP (internal Docker network)──▶ vulnscan ──HTTPS──▶ public feeds
                          Entra ID (OIDC)                                    /data volume
```

* **Inbound:** only to the sign-in gateway, over HTTPS, from the internal network or VPN. The vulnscan container publishes no port.
* **Outbound:** HTTPS GET requests to the addresses below, plus the gateway's calls to Microsoft Entra ID. Nothing is uploaded. Requests carry only date ranges and, if OSV is enabled, package names.
* **Stored:** the SQLite database and settings, in the `vulnscan-data` volume on the server.

## Outbound connections

| Host | Used for | Default |
|---|---|---|
| `services.nvd.nist.gov` | NIST NVD CVE API | on |
| `www.cisa.gov` | CISA Known Exploited Vulnerabilities list | on |
| `api.github.com` | GitHub global security advisories | on |
| `access.redhat.com` | Red Hat Security Data API | on |
| `euvdservices.enisa.europa.eu` | EU Vulnerability Database (ENISA) | on |
| `www.oracle.com` | Oracle Critical Patch Update pages | off |
| `www.ncsc.gov.ie` | NCSC Ireland news page | off |
| `aws.amazon.com` | AWS security bulletins RSS | off |
| `api.osv.dev` | OSV (sends the package names you list) | off |
| `login.microsoftonline.com` | Sign-in gateway: token exchange and signing keys | always |

**Only when building the image:**
* `pypi.org` and `files.pythonhosted.org` (Python packages).
* Docker Hub (`registry-1.docker.io`, `auth.docker.io`) for the Python base image, and `quay.io` for the gateway image.

Internal mirrors can be used instead.

## Authentication and authorisation

* **Sign-in is done by oauth2-proxy** (v7.7.1) using OpenID Connect with Microsoft Entra ID. VulnScan never sees passwords or tokens.
* **Access is limited twice:**
  * the Entra app's *Assignment required* setting;
  * `OAUTH2_PROXY_ALLOWED_GROUPS`.
* **The gateway passes the identity** in `X-Forwarded-Email` / `X-Forwarded-Groups`. It overwrites any such headers sent by a browser; the automated test sends forged ones and checks they are refused.
* **VulnScan refuses every request without that identity** (HTTP 401), except `/healthz`.
* **Roles:**
  * Viewer: read and export.
  * Admin (`VULNSCAN_ADMIN_GROUPS` / `VULNSCAN_ADMINS`): start scans, change and test sources.
  * Admin actions are logged with the person's name.
* **Desktop-only functions are disabled on the server:** API keys can't be set over the web, and there's no phone pairing and no remote shutdown.
* **Changes need a custom request header**, which blocks cross-site request forgery.
* **Session cookie:** `Secure`, `SameSite=Lax`, 8-hour lifetime. It is encrypted with a server-side secret.

## Secrets

| Secret | Where it lives |
|---|---|
| Entra client secret, cookie secret | `deploy/signin.env` on the server (not in git) |
| NVD API key | `deploy/secrets/nvd_api_key`, mounted as a Docker secret |

Nothing secret is in the image or the repository. The web screens show at most the last 4 characters of a key.

## Container hardening

* **Base image and libraries:** official `python:3.12-slim` image on Debian 13, with the latest Debian security updates applied at every build. Every Python package is pinned to an exact version in `requirements.txt`; the full list is in the image at `/app/installed-packages.txt`.
* **Runs as a non-root user** (UID 10001) with a **read-only root filesystem**. It can write only to `/data` and a temporary `/tmp`.
* **No extra privileges:** all Linux capabilities are dropped and `no-new-privileges` is set. No shell access is needed.
* **Web security headers** are sent on every page: Content-Security-Policy (no third-party content), X-Frame-Options DENY, nosniff, no-referrer.
* **Automated checks on every change** (GitHub Actions *Server image* workflow):
  * unit tests;
  * a sign-in and role test through the real gateway;
  * deployment file validation;
  * a vulnerability scan of the image (Trivy), also run every week. Rebuild the image (`docker compose up -d --build`) to pick up fixes.

## Handling of downloaded data

All feed content is treated as untrusted:
* It is parsed as JSON or XML. Feeds that declare XML entities are refused.
* It is stored as text and HTML-escaped before display.
* Links are shown only if they are `http(s)`.
* Nothing from a feed is executed.

## Known limitations

* **Single container, single database.** It is suitable for a team, but there is no high availability. If the server is lost, the data rebuilds itself on the next scan.
* **The identity headers are trusted.** That is why the vulnscan port must stay unpublished. Keep it that way.
* **The desktop app is a separate deployment.** Its executable is not code-signed yet; this document covers the server deployment.
