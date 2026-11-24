# Security review agent: Python + Semgrep + osv-scanner + gitleaks in one image.
FROM python:3.12-slim

ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG OSV_VERSION=2.7.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Download pinned scanner binaries and verify their SHA-256 checksums.
# A tampered or swapped download fails the build instead of running.
RUN set -eux; \
    ARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$ARCH" in \
      amd64) GL_ARCH=x64;   GL_SHA=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb; OSV_SHA=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b ;; \
      arm64) GL_ARCH=arm64; GL_SHA=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080; OSV_SHA=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7 ;; \
      *) echo "unsupported arch: $ARCH"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz"; \
    echo "${GL_SHA}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${ARCH}"; \
    echo "${OSV_SHA}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod +x /usr/local/bin/gitleaks /usr/local/bin/osv-scanner; \
    rm /tmp/gitleaks.tgz

# Pinned Python dependencies
RUN pip install --no-cache-dir semgrep==1.184.0 openai==3.48.0

# Run as a normal user, never root
RUN useradd --create-home --uid 1000 agent
USER agent
# The target repo is mounted read-only and owned by someone else; let git read it anyway
RUN git config --global --add safe.directory '*'

WORKDIR /app
COPY --chown=agent:agent agent.py tools.py compliance.py report.py entrypoint.sh ./
COPY --chown=agent:agent data ./data

ENV REPORTS_DIR=/out/reports \
    LOG_DIR=/out/logs \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["sh", "/app/entrypoint.sh"]