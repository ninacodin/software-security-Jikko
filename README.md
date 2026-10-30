# Team Jikko — NoteVault Secure Build

Term project for the Software Security course: threat-model, attack, fix and harden
**NoteVault**, a small Flask notes app.

**📄 Report: [`project/REPORT.md`](project/REPORT.md)**

## Layout

```
project/
├── REPORT.md            ← team report (submit this)
├── REPORT-TEMPLATE.md   ← course template
├── starter-app/         ← NoteVault — fixed code, Dockerfile, compose
├── tests/               ← regression tests
└── report/              ← each member's notes & evidence
    ├── person-a/        Injection & input, DFD, STRIDE
    ├── person-b/        Auth, session & crypto
    ├── person-c/        Access control & output
    └── person-d/        Supply chain, SBOM/Cosign, CI, demo script
.github/workflows/project-security.yml   ← security gate (Semgrep + Trivy + Gitleaks)
```

## Run

```bash
cd project/starter-app
export TEAM_ID=Jikko
export APP_SECRET=$(openssl rand -hex 32)   # required — the app refuses to start without it
docker compose up                            # http://localhost:8080
```

## Test

```bash
pip install -r project/starter-app/requirements.txt
APP_SECRET=test python -m unittest discover -s project/tests -p 'test_*.py' -v
```

> ⚠️ Sandbox only — see [ETHICS.md](ETHICS.md).
