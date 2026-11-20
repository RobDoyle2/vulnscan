#!/usr/bin/env bash
# End-to-end check of the server image with the sign-in gateway in front.
# Needs Docker and internet access. Usage: tools/server_smoke.sh [image]
# Uses a made-up Entra tenant: it checks the gateway sends people to Microsoft
# sign-in and that forged identity headers never reach VulnScan.
set -euo pipefail
IMAGE="${1:-vulnscan:test}"
T=00000000-1111-2222-3333-444444444444
NET=vs-smoke
cleanup() { docker rm -f vs-smoke-app vs-smoke-signin >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null
pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "PASS  $1 ($2)"; pass=$((pass+1)); else echo "FAIL  $1: expected $3, got $2"; fail=$((fail+1)); fi; }

docker run -d --name vs-smoke-app --network $NET --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true -e VULNSCAN_ADMINS=boss@example.com -e VULNSCAN_SCAN_EVERY_HOURS=999 \
  -p 127.0.0.1:18080:8080 "$IMAGE" >/dev/null
docker run -d --name vs-smoke-signin --network $NET -p 127.0.0.1:14180:4180 \
  -e OAUTH2_PROXY_PROVIDER=oidc -e OAUTH2_PROXY_OIDC_ISSUER_URL=https://login.microsoftonline.com/$T/v2.0 \
  -e OAUTH2_PROXY_SKIP_OIDC_DISCOVERY=true \
  -e OAUTH2_PROXY_LOGIN_URL=https://login.microsoftonline.com/$T/oauth2/v2.0/authorize \
  -e OAUTH2_PROXY_REDEEM_URL=https://login.microsoftonline.com/$T/oauth2/v2.0/token \
  -e OAUTH2_PROXY_OIDC_JWKS_URL=https://login.microsoftonline.com/$T/discovery/v2.0/keys \
  -e OAUTH2_PROXY_CLIENT_ID=test-client -e OAUTH2_PROXY_CLIENT_SECRET=test-secret \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(head -c 32 /dev/urandom | base64 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_EMAIL_DOMAINS='*' -e OAUTH2_PROXY_UPSTREAMS=http://vs-smoke-app:8080 \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 -e OAUTH2_PROXY_REDIRECT_URL=http://127.0.0.1:14180/oauth2/callback \
  -e OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true -e OAUTH2_PROXY_COOKIE_SECURE=false -e OAUTH2_PROXY_PASS_USER_HEADERS=true \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username quay.io/oauth2-proxy/oauth2-proxy:v7.7.1 >/dev/null
for i in $(seq 30); do curl -sf 127.0.0.1:18080/healthz >/dev/null && curl -s 127.0.0.1:14180/ping >/dev/null && break; sleep 1; done

A=127.0.0.1:18080; G=127.0.0.1:14180
echo "== VulnScan container (direct, as the gateway would call it)"
check "health check" "$(curl -s -o /dev/null -w '%{http_code}' $A/healthz)" 200
check "no sign-in refused" "$(curl -s -o /dev/null -w '%{http_code}' $A/)" 401
check "viewer can open page" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-Email: amy@example.com' $A/)" 200
check "viewer can read results" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-Email: amy@example.com' "$A/api/results?days=7")" 200
check "viewer cannot scan" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-VulnScan: 1' -H 'X-Forwarded-Email: amy@example.com' $A/api/scan -d '{}')" 403
check "admin can change settings" "$(curl -s -o /dev/null -w '%{http_code}' -X PUT -H 'X-VulnScan: 1' -H 'X-Forwarded-Email: boss@example.com' $A/api/settings -d '{"first_scan_days":1}')" 200
check "keys cannot be set over the web" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-VulnScan: 1' -H 'X-Forwarded-Email: boss@example.com' $A/api/secrets -d '{"name":"NVD_API_KEY","value":"x"}')" 403
check "runs as non-root (uid)" "$(docker exec vs-smoke-app id -u)" 10001
check "app files read-only" "$(docker exec vs-smoke-app sh -c 'touch /app/x 2>/dev/null && echo writable || echo read-only')" read-only

echo "== Through the sign-in gateway (oauth2-proxy, Entra ID settings)"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' $G/)
check "not signed in -> sent to Microsoft sign-in" "$(echo "$loc" | grep -o '^https://login.microsoftonline.com/' || echo "$loc")" "https://login.microsoftonline.com/"
check "forged identity header refused" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-Email: boss@example.com' -H 'X-Forwarded-User: boss' -H 'Accept: application/json' $G/api/results)" 401
check "forged identity cannot scan" "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-VulnScan: 1' -H 'X-Forwarded-Email: boss@example.com' -H 'Accept: application/json' $G/api/scan -d '{}')" 401
echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
