# NoteVault image — hardened for the term project (team Jikko).
#
# Baseline issues this file fixes:
#   - CWE-1104 unmaintained/unpinned base image  -> pin python:3.12-slim by digest
#   - CWE-250  running as root (Trivy DS-0002)   -> create and switch to a non-root user
#   - CWE-798  baked secret in ENV (Trivy DS-0031)-> removed; secrets come from runtime env
#   - oversized image / build cache leakage       -> slim base, --no-cache-dir, .dockerignore
#
# Base image pinned by digest (not the mutable :3.12 tag) so the build is
# reproducible and cannot be swapped under us — the Week 12 supply-chain control.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

# Don't buffer stdout/stderr (clean container logs) and don't write .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first (better layer caching), without keeping the pip cache.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the application code. A .dockerignore keeps everything else
# (evidence, SBOM, .git, caches) out of the build context.
COPY app.py .

# Run as an unprivileged user, not root.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8080

# No secrets baked into the image. TEAM_ID / TEAM_SALT / any app secret are
# supplied at runtime (docker compose environment / --env), never in a layer.
CMD ["python", "app.py"]
