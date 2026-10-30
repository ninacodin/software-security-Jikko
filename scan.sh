#!/usr/bin/env bash
# Run SAST + secret scanning on ./vulnerable-repo using Docker.
set -e
TARGET="${1:-./vulnerable-repo}"
echo "==> Semgrep (SAST)"
docker run --rm -v "$PWD/$TARGET:/src" semgrep/semgrep \
  semgrep --config p/default --config p/owasp-top-ten /src || true
echo
echo "==> Gitleaks (secret scanning)"
docker run --rm -v "$PWD/$TARGET:/repo" \
  zricethezav/gitleaks:latest detect --no-git -s /repo -v || true
