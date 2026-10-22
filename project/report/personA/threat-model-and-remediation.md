<!-- ============================================================================
     PERSON A DELIVERABLE — Supawan, 6631503042 — Injection & Input (Team Jikko)
     Branch: fix/injection-input-6631503042 · Fix commit: d66e777
     USAGE:
       • §2 + §3 below  -> you OWN these; commit into the team report (central deliverable).
       • §4 + §5 blocks -> hand to Person B, who assembles the full §4/§5.
       • DFD image: notevault-dfd.svg  (insert at the §2 "insert image" slot)
       • Evidence log: personA-evidence-beforeafter.md (source your stamped screenshots from it)
     TODO before submit: (1) stamped screenshots  (2) confirm OWASP Top 10:2025 numbering
                         (3) reword in your own voice (MOSS/JPlag + viva)
     ============================================================================ -->

# NoteVault — Secure Build · Person A sections (Injection & Input)

---

## 2. System Scope & Function

**NoteVault** is a small Flask web app + JSON API for team note-sharing. Users register/log in,
create private notes, search their own notes, and export them; an admin can list all users. Sessions
are carried in a signed JWT cookie. State lives in a SQLite database; `/export` shells out to an OS
command.

**In-scope components & endpoints**

| Component | Detail |
|---|---|
| Web/API process (P1) | Flask app, all routes below |
| Export subprocess (P2) | OS command spawned by `/export` |
| Database (D1) | SQLite at `/tmp/notevault.db` — `users` (username, password-hash, role), `notes` |
| Session token | JWT (HS256), signed with a server secret, stored client-side as the `session` cookie |
| Endpoints | `/` `/register` `/login` `/logout` `/notes` `/api/notes/<id>` `/search` `/admin` `/export` |

**Data-Flow Diagram (DFD):** see `notevault-dfd.svg`. Three trust boundaries:

- **TB1 — Internet ↔ App (network perimeter).** Every HTTP request crosses it; all input untrusted.
- **TB2 — App ↔ SQLite (query boundary).** Where untrusted input becomes SQL → SQL-injection surface (`/login`, `/search`).
- **TB3 — App ↔ OS shell (exec boundary).** Where untrusted input becomes a command → command-injection surface (`/export`).
- **TB4 — Client ↔ Server session trust.** Server trusts a JWT it signed; weak signing lets a client forge identity (Person B scope).

---

## 3. Threat Model — STRIDE  *(20 pts)*

STRIDE applied to each DFD element / flow. ✔ = a realistic threat exists in the current code.
Owner **A** = Injection & Input (my scope); others noted for completeness (whole-app model).

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| **TB1** HTTP request → P1 (all input) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Untrusted input is the root of every finding. Validate/encode at the boundary; authn+authz per route. |
| **F1/TB2** login creds → SQL *(A)* | ✔ | ✔ | | | | ✔ | **CWE-89 SQLi auth bypass** (`admin'-- -`). *Fix: parameterized query.* ✅ |
| **F4/TB2** search `q` → SQL *(A)* | | ✔ | | ✔ | | | **CWE-89 SQLi** `UNION SELECT` dumps all password hashes. *Fix: parameterized + `LIKE`/`ESCAPE`.* ✅ |
| **F5/TB3** export `fmt` → shell *(A)* | | ✔ | | ✔ | ✔ | ✔ | **CWE-78 command injection** (`fmt=txt;id` → RCE as root). *Fix: allowlist + `shell=False`.* ✅ |
| **F2/TB4** session JWT (verify) | ✔ | ✔ | ✔ | | | ✔ | **CWE-347** accepts `none` alg → forge admin. **CWE-798** hardcoded secret. *(Person B)* |
| **P1** `/register` role field | | | | | | ✔ | **CWE-269** client sets `role=admin` → privilege escalation. *(Person C)* |
| **F6** `/api/notes/<id>` | | | | ✔ | | ✔ | **CWE-639 IDOR** — any note by id, no owner check. *(Person C)* |
| **F6** `/admin` response | | | | ✔ | | | **CWE-200** returns raw username+password-hash list. *(Person C)* |
| **D1** stored password hashes | | | | ✔ | | | **CWE-327/916** unsalted MD5. *(Person B)* |
| **F3** note `body` rendered | | ✔ | | ✔ | | | **CWE-79 stored XSS** via `|safe` / `render_template_string`. *(Person C)* |
| **P1** Flask `debug=True` | | ✔ | | ✔ | | ✔ | **CWE-489** Werkzeug debugger → RCE/info leak. *(Person C)* |
| **P1/host** container runs as **root** | | ✔ | | | | ✔ | **CWE-250** no `USER` → process compromise = root. *(Person D)* |
| **F2** session cookie flags | ✔ | | ✔ | ✔ | | | **CWE-614/1004/352** no `HttpOnly`/`Secure`/CSRF. *(Person B)* |

### Top 5 risks (likelihood × impact)

| # | Risk | CWE | Likelihood | Impact | Rating | Owner |
|---|---|---|---|---|---|---|
| 1 | Command injection at `/export` → RCE as **root** in container | CWE-78 | High | Critical | **Critical** | A ✅ |
| 2 | JWT `none` alg / hardcoded secret → forge admin session | CWE-347/798 | High | Critical | **Critical** | B |
| 3 | SQLi at `/login` → authentication bypass | CWE-89 | High | High | **High** | A ✅ |
| 4 | SQLi at `/search` (`UNION`) → dump all credential hashes | CWE-89 | High | High | **High** | A ✅ |
| 5 | `/register` role injection → privilege escalation | CWE-269 | High | High | **High** | C |

*Risks 1, 3, 4 (injection scope) remediated on `fix/injection-input-6631503042`; see §4–§5. Risk 1 is
aggravated by #2-adjacent root container (Person D) — a cross-zone chain worth noting in the demo.*

---
<!-- ===== HAND THE TWO SECTIONS BELOW TO PERSON B FOR §4/§5 ASSEMBLY ===== -->

## 4. Vulnerability Findings — Injection & Input (Person A)

### Finding F-A1 — SQL Injection at `/login` (authentication bypass)
| Field | Value |
|---|---|
| CWE | CWE-89 (SQL Injection) |
| OWASP 2025 | A03:2025 – Injection *(confirm numbering)* |
| Severity | **High** |
| Location | `project/starter-app/app.py:128` (`/login`) |
| Root cause | Username & password hash concatenated with `%`-formatting into the SQL string; a `'` in `username` breaks out of the literal. |
| Reproduction | `POST /login` `username=admin'-- -` + any wrong `password` → `-- -` comments out the password check → returns the admin row. |
| Impact | Full auth bypass — log in as any user incl. `admin` without a password (HTTP 302 + session cookie). |
| Evidence | before: `302` + `Set-Cookie: session=…`; after: `401 login failed`. Screenshots: `screenshots/1-before-login.png`, `screenshots/4-after-login.png`. |

### Finding F-A2 — SQL Injection at `/search` (credential disclosure via UNION)
| Field | Value |
|---|---|
| CWE | CWE-89 (SQL Injection) |
| OWASP 2025 | A03:2025 – Injection *(confirm numbering)* |
| Severity | **High** |
| Location | `project/starter-app/app.py:178` (`/search`) |
| Root cause | Search term concatenated into SQL; the 3-column result set is reflected to the page → UNION extraction. |
| Reproduction | authenticated `GET /search?q=%' UNION SELECT id,username,password FROM users-- -` → appends every user's name + MD5 hash. |
| Impact | Disclosure of all usernames + password hashes; arbitrary table read → account takeover after offline cracking. |
| Evidence | before: lists `alice`/`admin` + hashes; after: empty `<ul></ul>`. Screenshots: `screenshots/2-before-search.png`, `screenshots/5-after-search.png`. |

### Finding F-A3 — OS Command Injection at `/export` (RCE as root)
| Field | Value |
|---|---|
| CWE | CWE-78 (OS Command Injection) |
| OWASP 2025 | A03:2025 – Injection *(confirm numbering)* |
| Severity | **Critical** |
| Location | `project/starter-app/app.py:202` (`/export`) |
| Root cause | `subprocess.run("echo exporting notes as " + fmt, shell=True)` — `fmt` is concatenated into a `/bin/sh` command; metacharacters (`;`, `|`, `` ` ``, `$()`) are interpreted. |
| Reproduction | authenticated `GET /export?fmt=txt;id` → shell runs `echo … ; id` → `uid=0(root)`. Aggravated by root container (Person D). |
| Impact | Arbitrary command execution as root inside the container — full host-process compromise. |
| Evidence | before: output contains `uid=0(root)`; after: `400 invalid format`. Screenshots: `screenshots/3-before-export.png`, `screenshots/6-after-export.png`. |

---

## 5. Remediation — Injection & Input (Person A)

All three fixed on branch `fix/injection-input-6631503042`, commit **`d66e777`**.

### Fix for F-A1 — parameterized login query
```diff
-    q = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (
-        username, hashlib.md5((password or "").encode()).hexdigest())
-    row = con.execute(q).fetchone()
+    q = "SELECT * FROM users WHERE username = ? AND password = ?"
+    pw_hash = hashlib.md5((password or "").encode()).hexdigest()
+    row = con.execute(q, (username, pw_hash)).fetchone()
```
- **Why:** values are bound as data, never parsed as SQL. `admin'-- -` becomes a literal username that matches no row → `401`. (MD5 left intentionally — Person B's crypto finding.)
- **Proof exploit fails:** `username=admin'-- -` → `401 login failed` *(verified by running, 2026-10-22)* — see `screenshots/4-after-login.png`.

### Fix for F-A2 — parameterized search + LIKE escaping
```diff
-    q = "SELECT id,title,body FROM notes WHERE owner='%s' AND body LIKE '%%%s%%'" % (user, term)
-    rows = con.execute(q).fetchall()
+    like = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
+    q = "SELECT id,title,body FROM notes WHERE owner = ? AND body LIKE ? ESCAPE '\\'"
+    rows = con.execute(q, (user, "%" + like + "%")).fetchall()
```
- **Why:** the term is bound, so `UNION SELECT …` can't break out; `ESCAPE '\'` + pre-escaping `% _ \` makes wildcards match literally.
- **Proof exploit fails:** UNION payload → empty result; `%'` searched as literal text *(verified by running)* — see `screenshots/5-after-search.png`.

### Fix for F-A3 — allowlist + shell=False
```diff
-    out = subprocess.run("echo exporting notes as " + fmt, shell=True,
+    allowed = {"txt", "csv", "json"}
+    if fmt not in allowed:
+        return "invalid format", 400
+    out = subprocess.run(["echo", "exporting notes as", fmt], shell=False,
                          capture_output=True, text=True)
```
- **Why:** defence-in-depth — (1) allowlist rejects anything but `txt/csv/json` → `400`; (2) `shell=False` + argv list means no value is ever parsed by a shell. Either layer alone stops the attack.
- **Proof exploit fails:** `?fmt=txt;id` → `400 invalid format`; `?fmt=csv` still returns `exporting notes as csv` (legit use preserved) *(verified by running)* — see `screenshots/6-after-export.png`.
