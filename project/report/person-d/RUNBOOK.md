# Runbook — reproduce the Person D artifacts

All commands run from the repo root on Windows (PowerShell). Tools that aren't
installed locally are run via their official Docker images. `cosign` is native.
`$repo` = repo root; set `$repo = (Get-Location).Path` first.

## 0. Run the app (seeds the team marker)
```powershell
cd project/starter-app
$env:TEAM_ID = "Jikko"
docker compose up -d --build        # http://localhost:8080  (alice/alicepw, admin/admin123)
```

## 1. Baseline scans ("before")
```powershell
$ev = "project\report\person-d\evidence\before"
# Trivy: deps + Dockerfile misconfig + secrets, HIGH/CRITICAL
docker run --rm -v "${repo}:/src" aquasec/trivy:latest fs --scanners vuln,secret,misconfig `
  --severity HIGH,CRITICAL --no-progress --quiet /src/project/starter-app > "$ev\trivy-fs.txt"
# pip-audit
docker run --rm -v "${repo}:/src" python:3.12-slim sh -c `
  "pip install -q pip-audit; pip-audit -r /src/project/starter-app/requirements.txt" > "$ev\pip-audit.txt"
# Gitleaks
docker run --rm -v "${repo}:/src" ghcr.io/gitleaks/gitleaks:latest dir /src/project/starter-app -v > "$ev\gitleaks.txt"
```

## 2. Remediate deps  (resolve exact secure pins, then edit requirements.txt)
```powershell
docker run --rm python:3.12-slim sh -c "pip install -q --upgrade Flask Jinja2 PyJWT; pip freeze"
```

## 3. Rebuild + verify ("after")
```powershell
cd project/starter-app; $env:TEAM_ID = "Jikko"; docker compose up -d --build; cd $repo
docker compose -f project/starter-app/docker-compose.yml exec -T notevault whoami   # -> appuser
$ev = "project\report\person-d\evidence\after"
docker run --rm -v "${repo}:/src" aquasec/trivy:latest fs --scanners vuln,secret,misconfig `
  --severity HIGH,CRITICAL --no-progress --quiet /src/project/starter-app > "$ev\trivy-fs.txt"
```

## 4. SBOM (CycloneDX)
```powershell
docker run --rm -v "${repo}:/src" -v "//var/run/docker.sock:/var/run/docker.sock" `
  aquasec/trivy:latest image --quiet --format cyclonedx `
  -o /src/project/report/person-d/sbom/sbom.json starter-app-notevault:latest
```

## 5. Sign with Cosign (local registry, no external account)
```powershell
docker run -d -p 5000:5000 --name reg registry:2
docker tag starter-app-notevault:latest localhost:5000/notevault:1.0.0
docker push localhost:5000/notevault:1.0.0            # note the sha256 digest
cd project/report/person-d/cosign
$env:COSIGN_PASSWORD = "jikko-demo"                   # throwaway demo key
cosign generate-key-pair
$d = "<digest-from-push>"
cosign sign   --yes --key cosign.key --allow-insecure-registry "localhost:5000/notevault@$d"
cosign verify        --key cosign.pub --allow-insecure-registry "localhost:5000/notevault@$d" | Tee-Object verify-output.txt
# SBOM attestation
cosign attest --yes --key cosign.key --allow-insecure-registry --type cyclonedx --predicate ..\sbom\sbom.json "localhost:5000/notevault@$d"
cosign verify-attestation --key cosign.pub --allow-insecure-registry --type cyclonedx "localhost:5000/notevault@$d" | Tee-Object verify-attestation.txt
```

## 6. Prove the CI SAST gate fires (Semgrep)
```powershell
docker run --rm -v "${repo}:/src" semgrep/semgrep `
  sh -c "cp -r /src/project/starter-app /scan && cd /scan && semgrep scan --config p/default --config p/owasp-top-ten --severity ERROR --error ."
# exit code 1 = gate would fail the build
```

## Cleanup
```powershell
docker compose -f project/starter-app/docker-compose.yml down
docker rm -f reg
```
