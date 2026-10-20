# Team Jikko — Supply-Chain & Build/CI (Person D)

Deliverables for sections **§6 (supply-chain hardening)** and **§7 (security CI)**
of the term-project report, plus the dependency/Dockerfile remediation.
Everything here was produced by *running* the tools, not by reading — outputs are
checked in under `evidence/` and `sbom/`.

## Results at a glance

| Area | Before | After | Evidence |
|---|---|---|---|
| Python deps (Trivy) | 16 CVEs — HIGH 15, CRITICAL 1 | **0** | `evidence/{before,after}/trivy-fs.txt` |
| Python deps (pip-audit) | 80 advisories / 7 pkgs | **0** | `evidence/{before,after}/pip-audit.txt` |
| Dockerfile misconfig (Trivy) | HIGH 1 (root), CRITICAL 1 (baked secret) | **0** | `evidence/{before,after}/trivy-fs.txt` |
| Secret scan (Gitleaks) | 0 (see note) | 0 | `evidence/before/gitleaks.txt` |
| Semgrep SAST gate | 11 blocking (exit 1) | — app-code, owned by A–C | `evidence/ci/semgrep-baseline.txt` |

> **Gitleaks note:** NoteVault's baked secret (`notevault-dev-secret`, `hunter2`)
> is low-entropy and does **not** match Gitleaks' default rules. The Trivy
> misconfig scanner (`DS-0031`, CRITICAL) is what catches the baked `ENV` secret.
> Our CI keeps Gitleaks for real credential formats and relies on Trivy for this.

## What changed (per-finding commits on branch `harden/supply-chain`)

1. `fix(deps)` — `requirements.txt` bumped to patched, fully-pinned releases;
   removed unused `requests`/`urllib3`. **[CWE-1395]**
2. `fix(docker)` — pinned base by digest, non-root `appuser`, removed baked
   `ENV` secret, slim base + `--no-cache-dir` + `.dockerignore`. **[CWE-250, CWE-798]**

## SBOM + signing (§6)

- `sbom/sbom.json` — CycloneDX 1.7, **97 components**, generated from the built image.
- `cosign/cosign.pub` — public key. `cosign/verify-output.txt` +
  `cosign/verify-attestation.txt` — `cosign verify` / `verify-attestation` output.
- The signing **private key is intentionally not committed** (`cosign/.gitignore`).

## CI pipeline (§7)

`.github/workflows/project-security.yml` — a **separate** workflow from the
course's `security-ci.yml` (which deliberately excludes `project/starter-app`).
Three gates, fail on HIGH/CRITICAL:
- **SAST** — Semgrep (`p/default` + `p/owasp-top-ten`), copies the app out of the
  repo first so the root `.semgrepignore` can't zero out the scan.
- **SCA + misconfig + secrets** — Trivy fs scan of `project/starter-app`.
- **Secrets** — Gitleaks.

See `RUNBOOK.md` for the exact commands to reproduce every artifact here.
