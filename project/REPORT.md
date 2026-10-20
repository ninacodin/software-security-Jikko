# Term Project Report — Secure Build

> Working copy. Filled section-by-section per `REPORT-TEMPLATE.md`. Total **100 pts**.
> **Assembly owner:** คน B — keeps §1 (Executive Summary) and §4 (Findings assembly) in sync.
> `<!-- TODO -->` marks a slot a teammate still needs to fill.

## Cover

| Field | Value |
|---|---|
| Team name | `<!-- TODO -->` |
| Members (name + ID) | `<!-- TODO -->` |
| Target application | NoteVault (`project/starter-app/`) |
| Repository URL | https://github.com/<team>/software-security-Jikko (fork of nutthakorn7/software-security) |
| Date | 2026-10-20 |

## AI-tool usage disclosure

| Tool | How it was used |
|---|---|
| Claude Code (Opus 4.8) | Reviewing the auth/session/crypto code, drafting the fixes on `remediation/auth-session-crypto`, and drafting §1/§4/§5 for those findings. All fixes reviewed by the team. |
| `<!-- TODO: teammates add their tools -->` | |

---

## 1. Executive Summary

*(DRAFT — numbers cover the auth/session/crypto workstream only; update totals once
input-handling, access-control, supply-chain and container findings are merged.)*

NoteVault is a small Flask note-sharing web app + JSON API (register/login with a cookie
session, per-user notes, search, an admin user list, and an export endpoint). A security
review found vulnerabilities spanning input handling, access control, **sessions and
cryptography**, dependencies, and container/build configuration.

**Findings by severity (so far):**

| Severity | Count | Examples |
|---|---|---|
| Critical | 1 | JWT `alg:none` accepted → full admin impersonation |
| High | 2 | Hard-coded signing key; unsalted MD5 password hashing |
| Medium | 2 | Session cookie without security flags; session tokens never expire |
| — | `<!-- TODO: + input-handling / access-control / supply-chain / container findings -->` | |

**Risk before:** an unauthenticated attacker could forge an admin session token and take
over the application; stored credentials were trivially crackable. **Risk after (this
workstream):** session tokens are signed with a runtime-injected key, restricted to `HS256`,
time-limited, and carried in a hardened cookie; passwords use bcrypt with per-hash salts.

---

## 2. System Scope & Function

- Endpoints: `/` `/register` `/login` `/logout` `/notes` `/api/notes/<id>` `/search` `/admin` `/export`.
- Session: signed JWT in a `session` cookie; `current_user()` decodes it on each request.
- Data store: SQLite (`/tmp/notevault.db`), tables `users` and `notes`.
- **DFD + trust boundaries:** `<!-- TODO: threat-model owner inserts diagram -->`

---

## 3. Threat Model — STRIDE  *(20 pts)*

`<!-- TODO: threat-model owner -->`

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

---

## 4. Vulnerability Findings  *(25 pts)*

> IDs are prefixed by workstream owner (B = auth/session/crypto). Assembly owner renumbers
> to F-01… once every team member's findings are in.

### Finding B1 — JWT `alg:none` accepted (authentication bypass)
| Field | Value |
|---|---|
| CWE | CWE-347 Improper Verification of Cryptographic Signature |
| OWASP 2025 | A07 Identification and Authentication Failures |
| Severity | **Critical** |
| Location | `project/starter-app/app.py:83` (`current_user()`) |
| Reproduction | The server called `jwt.decode(tok, SECRET, algorithms=["HS256", "none"])`, so a token whose header is `{"alg":"none"}` with an **empty signature** and payload `{"sub":"admin"}` is accepted without any signature check. Submit that token as the `session` cookie → the app treats you as `admin`. |
| Impact | Any unauthenticated attacker gains full access as any user, including admin (reads every user's notes, the admin panel, etc.). Complete authentication bypass. |
| Evidence | `<!-- TODO: screenshot of forged-token request returning admin content -->` |

### Finding B2 — Hard-coded session-signing key
| Field | Value |
|---|---|
| CWE | CWE-798 Use of Hard-coded Credentials |
| OWASP 2025 | A07 Identification and Authentication Failures |
| Severity | **High** |
| Location | `project/starter-app/app.py:23` + `Dockerfile` (`ENV APP_SECRET=...`) |
| Reproduction | The HMAC key `SECRET = "notevault-dev-secret"` is in the source and baked into the image. Anyone with the repo or image reads it, then signs their own valid `HS256` token `{"sub":"admin"}`. |
| Impact | Token forgery for any user even after B1 is fixed; the key cannot be rotated without a code/image change. |
| Evidence | `<!-- TODO: show secret in source + a self-signed token accepted -->` |

### Finding B3 — Passwords hashed with unsalted MD5
| Field | Value |
|---|---|
| CWE | CWE-327 Broken Crypto Algorithm; CWE-916 Insufficient Computational Effort |
| OWASP 2025 | A02 Cryptographic Failures |
| Severity | **High** |
| Location | `project/starter-app/app.py:68-69` (seed), `:117` (register), `:129` (login) |
| Reproduction | Stored passwords are `hashlib.md5(pw).hexdigest()` with no salt. Dump the `users` table (e.g. via the admin panel / SQLi) and crack the hashes instantly with a rainbow table or `hashcat -m 0`; identical passwords share a hash. |
| Impact | Mass credential disclosure on any DB leak; fast offline cracking. |
| Evidence | `<!-- TODO: show MD5 hash cracked to plaintext -->` |

### Finding B4 — Session cookie without security flags
| Field | Value |
|---|---|
| CWE | CWE-614 Sensitive Cookie Without 'Secure' Attribute (+ missing HttpOnly) |
| OWASP 2025 | A05 Security Misconfiguration |
| Severity | Medium |
| Location | `project/starter-app/app.py:136` (`resp.set_cookie("session", tok)`) |
| Reproduction | The `Set-Cookie` response carries no `HttpOnly`, `Secure`, or `SameSite`. JS (`document.cookie`) can read the token (XSS exfiltration), it may be sent over plain HTTP, and it has no CSRF defence. |
| Impact | Session theft via XSS or network interception; CSRF exposure. |
| Evidence | `<!-- TODO: show raw Set-Cookie header lacking flags -->` |

### Finding B5 — Session tokens never expire
| Field | Value |
|---|---|
| CWE | CWE-613 Insufficient Session Expiration |
| OWASP 2025 | A07 Identification and Authentication Failures |
| Severity | Medium |
| Location | `project/starter-app/app.py:134` (`jwt.encode({"sub": username}, ...)`) |
| Reproduction | Tokens are minted with no `exp` claim, so a captured token stays valid indefinitely — it never ages out and there is no revocation. |
| Impact | A stolen/leaked token grants permanent access. |
| Evidence | `<!-- TODO: show an old token still accepted -->` |

> `<!-- TODO: teammates append F-? for SQLi (/search), XSS (/search), command injection
> (/export), IDOR (/api/notes), admin password exposure, debug=True, vulnerable deps,
> and the Dockerfile (root user, unpinned base). -->`

---

## 5. Remediation  *(25 pts)*  — auth/session/crypto fixes

Branch: `remediation/auth-session-crypto`.

### Fix for B1 — restrict JWT algorithms  · commit `47b12b6`
```diff
- data = jwt.decode(tok, SECRET, algorithms=["HS256", "none"])
+ data = jwt.decode(tok, SECRET, algorithms=["HS256"])
```
- **Why this fixes it:** removing `"none"` means an unsigned token is no longer a valid algorithm, so every token must carry a real HMAC signature made with the server key.
- **Proof the exploit now fails (verified):** forged token `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.` (`{"alg":"none"}` / `{"sub":"admin"}`, empty signature) sent as the `session` cookie — `GET /` renders the **login form** (unauthenticated) and `GET /admin` returns **`HTTP/1.0 403 FORBIDDEN`**. `<!-- optional: add screenshot -->`

### Fix for B2 — key from env, not baked in  · commit `caff106`
```diff
- SECRET = "notevault-dev-secret"  # used to sign session tokens
+ SECRET = os.environ["APP_SECRET"]  # supplied at runtime
```
```diff
# Dockerfile
- ENV APP_SECRET=notevault-dev-secret
# docker-compose.yml
+ - APP_SECRET=${APP_SECRET:?set APP_SECRET in your shell before starting}
```
- **Why this fixes it:** the key is no longer in source or image; it is injected at runtime and can be rotated. App fails closed at startup if it is missing.
- **Proof (verified):** with `APP_SECRET` unset, `docker compose up` aborts: *"required variable APP_SECRET is missing a value: set APP_SECRET in your shell before starting"* — the app never starts with a default key.

### Fix for B3 — bcrypt instead of MD5  · commit `29a125e`
```diff
- (username, hashlib.md5(password.encode()).hexdigest(), role)
+ (username, hash_pw(password), role)
```
```diff
# /login
- q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, md5(...))
- row = con.execute(q).fetchone()
- if not row:
+ row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
+ if not row or not verify_pw(password, row["password"]):
      return "login failed", 401
```
- **Why this fixes it:** bcrypt adds a per-hash random salt and an adaptive work factor; `verify_pw` is constant-time. The login lookup is now parameterized (bcrypt hashes can't be matched in SQL), which also closes the injection in this one query.
- **Note:** `bcrypt==4.2.1` added to `requirements.txt`.
- **Proof (verified):** seeded rows now store `$2b$12$…` bcrypt hashes (not 32-hex MD5); `POST /login` alice/alicepw → `HTTP 302` (success), wrong password → `HTTP 401`.

### Fix for B4 — harden the session cookie  · commit `b576f57`
```diff
- resp.set_cookie("session", tok)
+ resp.set_cookie("session", tok, httponly=True, secure=True, samesite="Lax")
```
- **Why this fixes it:** `HttpOnly` blocks JS access, `Secure` restricts the cookie to HTTPS, `SameSite=Lax` mitigates CSRF.
- **Proof (verified):** login response header — `Set-Cookie: session=…; Secure; HttpOnly; Path=/; SameSite=Lax`.

### Fix for B5 — expire session tokens  · commit `59132fa`
```diff
- tok = jwt.encode({"sub": username}, SECRET, algorithm="HS256")
+ now = datetime.now(timezone.utc)
+ tok = jwt.encode({"sub": username, "iat": now, "exp": now + timedelta(hours=1)},
+                  SECRET, algorithm="HS256")
```
- **Why this fixes it:** tokens carry a 1-hour `exp`; `jwt.decode()` rejects expired tokens automatically, so a leaked token ages out.
- **Proof (verified):** issued token payload decodes to `{"sub":"alice","iat":1792487370,"exp":1792490970}` — `exp − iat = 3600 s` (1 hour).

---

## 6. Supply-Chain Hardening  *(15 pts)*
`<!-- TODO: SBOM + Cosign owner -->`

## 7. Security CI Pipeline  *(10 pts)*
`<!-- TODO: CI owner -->`

## 8. Conclusion & Reflection  *(5 pts)*
`<!-- TODO -->`

## Appendix
- **Task split:** คน B — Auth/Session/Crypto (findings B1–B5) + report assembly (§1, §4).
- References: CWE (cwe.mitre.org), OWASP Top 10:2025.
