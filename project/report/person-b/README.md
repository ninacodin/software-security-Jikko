# Person B — Authentication, Session & Crypto

Findings **F-04 – F-08** in the team report (internal IDs B1–B5).

| Report ID | Internal | Finding | CWE | Fix commit |
|---|---|---|---|---|
| F-04 | B2 | Hard-coded session-signing key | CWE-798 | `caff106` |
| F-05 | B1 | `alg:none` in JWT allowlist | CWE-347 | `47b12b6` |
| F-06 | B3 | Unsalted MD5 passwords → bcrypt | CWE-327/916 | `29a125e` |
| F-07 | B4 | Session cookie flags | CWE-614 | `b576f57` |
| F-08 | B5 | Session tokens never expire | CWE-613 | `59132fa` |

- [`draft-report.md`](draft-report.md) — B's original assembled draft (before the four sections
  were merged into [`../../REPORT.md`](../../REPORT.md)); kept for history.
- Running the app now requires `APP_SECRET` in the environment (fix for F-04):
  `export APP_SECRET=$(openssl rand -hex 32)` before `docker compose up`.
