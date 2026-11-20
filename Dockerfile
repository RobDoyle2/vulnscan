# VulnScan server image. Build:  docker build -t vulnscan:1.0.0 .
# Runs as a non-root user, keeps all data in /data, works with a read-only
# root filesystem. Sign-in is handled by the gateway in deploy/docker-compose.yml.
FROM python:3.12.16-slim-trixie

# Apply the latest Debian security updates on every build.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VULNSCAN_HOME=/data \
    VULNSCAN_PORT=8080

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin vulnscan \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY requirements.txt .
# Behind a proxy that inspects HTTPS, pass the company root certificate at build
# time:  docker build --secret id=company_ca,src=company-root.pem ...
# It is used only for this step and is not kept in the image.
RUN --mount=type=secret,id=company_ca,required=false \
    if [ -s /run/secrets/company_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/company_ca > /tmp/build-ca.pem; \
      export PIP_CERT=/tmp/build-ca.pem; \
    fi; \
    pip install -r requirements.txt && pip freeze > /app/installed-packages.txt && rm -f /tmp/build-ca.pem
COPY run.py collector.py report.py ./
COPY vulnscan_app ./vulnscan_app

USER 10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)" || exit 1
ENTRYPOINT ["python", "run.py", "--server"]
