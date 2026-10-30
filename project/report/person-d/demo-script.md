# Demo script — Person D (Supply-Chain & Build/CI)

~3–4 minutes of the team's Week-19 video. Structure each part as **attack → root
cause → fix**. Commands are copy-paste ready (run from repo root; `$env:TEAM_ID="Jikko"`).

Keep both branches handy: `main` / `ci-demo-baseline` = vulnerable, `harden/supply-chain` = fixed.

---

## Part 1 — Insecure container (root + baked secret)  (~60s)

**Attack / show the problem**
```powershell
git checkout main
docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs --scanners misconfig `
  --severity HIGH,CRITICAL --quiet /src/project/starter-app
```
→ point at `DS-0031 CRITICAL` (secret in `ENV APP_SECRET`) and `DS-0002 HIGH` (runs as root).

**Root cause** — one line each: the secret is baked into an image layer (ships with
the image, visible in `docker history`); with no `USER`, a code-exec bug in the app
runs as root inside the container.

**Fix**
```powershell
git checkout harden/supply-chain
# show the Dockerfile: digest-pinned base, no ENV secret, USER appuser
docker compose -f project/starter-app/docker-compose.yml up -d --build
docker compose -f project/starter-app/docker-compose.yml exec -T notevault whoami   # -> appuser
docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs --scanners misconfig `
  --severity HIGH,CRITICAL --quiet /src/project/starter-app                          # -> 0
```

---

## Part 2 — Vulnerable dependencies  (~60s)

**Attack**
```powershell
git checkout main
docker run --rm -v "${PWD}:/src" python:3.12-slim `
  sh -c "pip install -q pip-audit; pip-audit -r /src/project/starter-app/requirements.txt" | Select-Object -First 15
```
→ "Found 80 known vulnerabilities in 7 packages."

**Root cause** — pinned to years-old releases; e.g. **PyJWT 1.7.1** has a forged-token
auth-bypass CVE — directly relevant since NoteVault uses JWT sessions. `requests`/`urllib3`
were pulled in but never imported.

**Fix**
```powershell
git checkout harden/supply-chain
docker run --rm -v "${PWD}:/src" python:3.12-slim `
  sh -c "pip install -q pip-audit; pip-audit -r /src/project/starter-app/requirements.txt"   # -> No known vulnerabilities found
```
→ patched + pinned, unused deps removed.

---

## Part 3 — SBOM + signing + CI gate  (~60–90s)

**SBOM + signature**
```powershell
# SBOM: CycloneDX 1.7, 97 components  (project/report/person-d/sbom/sbom.json)
cat project/report/person-d/cosign/verify-output.txt        # cosign verify: signatures verified
```
Say: "We generate a CycloneDX SBOM from the image, sign the image with Cosign, and
attach a signed SBOM attestation — so a consumer can verify both *what's inside* and
*that we built it*."

**CI gate (the money shot)** — open the two Actions runs:
- Baseline: Trivy job **red** on HIGH/CRITICAL →
  `https://github.com/ninacodin/software-security-Jikko/actions/runs/39839508883`
- After fixes: Trivy job **green** →
  `https://github.com/ninacodin/software-security-Jikko/actions/runs/39839516007`

Say: "The pipeline fails the build on any HIGH/CRITICAL finding. Our fixes turn the
SCA/misconfig gate from red to green; the SAST gate stays red until the app-code
findings (SQLi, JWT `alg:none`, IDOR…) are fixed by the rest of the team."

---

## Likely viva questions — have answers ready
- **Why remove `requests`/`urllib3` instead of upgrading?** Not imported anywhere;
  removing unused deps is a smaller, safer change and shrinks the attack surface.
- **What does pinning the base by digest buy you that a tag doesn't?** A tag is
  mutable — `python:3.12` can be repointed to a different image; a digest is
  content-addressed and immutable, so the build is reproducible and tamper-evident.
- **Why didn't Gitleaks catch the baked secret?** It's a low-entropy string that
  matches no default rule; Trivy's misconfig scanner (DS-0031) flags the `ENV`
  secret instead. We document that split and keep Gitleaks for real credential formats.
- **Is this SLSA L2?** No — L1 (verifiable provenance exists). L2 needs the build
  service to generate and sign provenance; our path is keyless Cosign in CI.
- **Why a separate CI workflow?** The course `security-ci.yml` intentionally excludes
  the vulnerable teaching material; widening it would break other lessons, so we add
  a project-scoped workflow instead.
