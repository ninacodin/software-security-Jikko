# Report content — Person D (Supply-Chain & Build/CI)

Ready to paste into `project/REPORT-TEMPLATE.md`. Covers the two Person-D findings
(§4/§5), supply-chain hardening (§6), and the CI pipeline (§7). All numbers come
from running the tools; raw output is under `evidence/`, `sbom/`, `cosign/`.

> **OWASP 2025 mapping — confirm the exact Axx number against the course handout.**
> The 2025 list renamed/reordered categories. The *category names* below are
> stable; the numbers are our best reading and should be checked before submission.

---

## §4 — Findings (Person D's two)

### Finding F-D1 — Vulnerable & outdated dependencies
| Field | Value |
|---|---|
| CWE | CWE-1395 (dependency on vulnerable third-party component); incl. CWE-1104 |
| OWASP 2025 | **Software Supply Chain Failures** (A03:2025) |
| Severity | High |
| Location | `project/starter-app/requirements.txt` |
| Reproduction | `docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs --scanners vuln --severity HIGH,CRITICAL /src/project/starter-app` |
| Impact | 16 HIGH/CRITICAL CVEs (80 advisories via pip-audit) across Flask, Werkzeug, Jinja2, PyJWT, urllib3. Notably **PyJWT 1.7.1** → auth-bypass/forged-token CVEs; **Jinja2 3.0.1** → sandbox-escape RCE; **Werkzeug 2.0.1** → debugger/multipart DoS. |
| Evidence | `evidence/before/trivy-fs.txt`, `evidence/before/pip-audit.txt` |

### Finding F-D2 — Insecure container build (root + baked secret + unpinned base)
| Field | Value |
|---|---|
| CWE | CWE-250 (running as root), CWE-798 (hardcoded secret in image), CWE-1104 (unpinned base) |
| OWASP 2025 | **Security Misconfiguration** (A02:2025) |
| Severity | Critical (baked secret) / High (root) |
| Location | `project/starter-app/Dockerfile` (`FROM python:3.12`, `ENV APP_SECRET=…`, no `USER`) |
| Reproduction | `trivy fs --scanners misconfig /src/project/starter-app` → `DS-0002` (HIGH), `DS-0031` (CRITICAL) |
| Impact | Container runs as root → a code-exec bug becomes host-level risk; the secret is baked into an image layer and leaks with the image; a mutable `:3.12` tag lets the base be swapped under the build. |
| Evidence | `evidence/before/trivy-fs.txt` (Dockerfile section) |

---

## §5 — Remediation

### Fix for F-D1 — dependencies  ·  commit `c8a2c7d`
```diff
- Flask==2.0.1
- Werkzeug==2.0.1
- Jinja2==3.0.1
- PyJWT==1.7.1
- requests==2.25.1      # unused — not imported anywhere in app.py
- urllib3==1.26.4       # unused
+ Flask==3.1.3
+ Werkzeug==3.1.9
+ Jinja2==3.1.6
+ MarkupSafe==3.0.4
+ itsdangerous==2.2.0
+ click==8.5.0
+ blinker==1.9.0
+ PyJWT==2.15.1
```
- **Why this fixes it:** bumps every flagged package to a patched release and pins
  transitive deps for a reproducible build. `requests`/`urllib3` are removed
  entirely (confirmed unused), shrinking the attack surface rather than patching
  code we don't run.
- **Proof the exploit now fails:** `evidence/after/trivy-fs.txt` → **0** vulns;
  `evidence/after/pip-audit.txt` → "No known vulnerabilities found". App still
  serves HTTP 200.

### Fix for F-D2 — Dockerfile  ·  commit `86655f9`
```diff
- FROM python:3.12
- ENV APP_SECRET=notevault-dev-secret
- COPY . .
- RUN pip install -r requirements.txt
+ FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
+ COPY requirements.txt .
+ RUN pip install --no-cache-dir -r requirements.txt
+ COPY app.py .
+ RUN useradd --create-home --uid 10001 appuser
+ USER appuser
```
- **Why this fixes it:** base pinned by **digest** (immutable); the baked `ENV`
  secret is gone (secrets come from runtime env only); the image runs as a
  non-root `appuser`; `slim` base + `--no-cache-dir` + a `.dockerignore` allowlist
  (only `app.py`, `requirements.txt`) keep the image minimal and the build context
  clean.
- **Proof the exploit now fails:** `trivy fs --scanners misconfig` → **0**
  Dockerfile misconfigurations; `docker compose exec notevault whoami` → `appuser`.

---

## §6 — Supply-Chain Hardening

- **SBOM:** `sbom/sbom.json` — **CycloneDX 1.7, 97 components**, generated from the
  built image with Trivy:
  `trivy image --format cyclonedx -o sbom.json starter-app-notevault:latest`.
- **Signing (Cosign):** image signed by digest with a key pair; signature and a
  CycloneDX **SBOM attestation** both verify. Public key + outputs in `cosign/`.
  ```
  cosign verify --key cosign.pub localhost:5000/notevault@sha256:068f72af…
  Verification for localhost:5000/notevault@sha256:068f72af… --
    - The cosign claims were validated
    - Existence of the claims in the transparency log was verified offline
    - The signatures were verified against the specified public key
  ```
  (Full output: `cosign/verify-output.txt`, `cosign/verify-attestation.txt`.)
- **SLSA self-assessment — Build Level 1 (with a clear path to L2).** Source is
  version-controlled; the build is scripted (Dockerfile) and produces a signed
  artifact plus a signed SBOM attestation, so *provenance exists and is
  verifiable* — meeting L1. We do **not** yet reach L2, which requires the
  provenance to be generated by a hosted build service and signed by the builder
  (not by us locally). Path to L2: move the build+sign into the GitHub Actions
  workflow using keyless (OIDC) Cosign so the CI platform attests provenance.

---

## §7 — Security CI Pipeline

- **Workflow:** `.github/workflows/project-security.yml` — a **separate** workflow
  from the course's `security-ci.yml` (which deliberately excludes
  `project/starter-app`). Three gates, fail on HIGH/CRITICAL:
  - **SAST** — Semgrep (`p/default` + `p/owasp-top-ten`). Copies the app out of
    the repo first, because the repo-root `.semgrepignore` lists
    `project/starter-app/` and would otherwise zero out the scan (a false pass).
  - **SCA + misconfig + secrets** — Trivy fs scan, `--severity HIGH,CRITICAL`,
    `exit-code 1`.
  - **Secrets** — Gitleaks `dir` over the app only (`--no-git`), pinned v8.24.3.
- **Proof the gate fails on HIGH/CRITICAL** — two real runs:

  | Job | Baseline (vulnerable) | After Person-D fixes |
  |---|---|---|
  | Trivy (SCA + misconfig) | 🔴 **failure** — HIGH/CRIT deps + Dockerfile | 🟢 success |
  | Semgrep (SAST) | 🔴 failure — app-code vulns (owned by A–C) | 🔴 failure (pending A–C) |
  | Gitleaks | 🟢 success | 🟢 success |

  - Baseline run (Trivy red): `https://github.com/ninacodin/software-security-Jikko/actions/runs/39839508883`
  - After-fix run (Trivy green): `https://github.com/ninacodin/software-security-Jikko/actions/runs/39839516007`
  - **Screenshot the baseline run's failing Trivy job for the report.**

- **How the gate is configured:** each scanner runs with an explicit
  HIGH/CRITICAL (or ERROR) threshold and a non-zero exit on findings, so any such
  finding fails the job and blocks the build.

- **Honest coverage note:** Gitleaks' default rules do **not** flag NoteVault's
  low-entropy baked secret (`notevault-dev-secret`); **Trivy's misconfig scanner
  (DS-0031) catches it instead.** We also hit — and fixed — a Gitleaks false
  positive where scanning full git history flagged a sample PEM key quoted inside
  a CVE description in our own evidence file (commit `149f636`).
