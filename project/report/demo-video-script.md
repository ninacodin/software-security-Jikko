# Demo Video Script — Team Jikko · NoteVault Secure Build

> Format required: **attack → root cause → fix**, uploaded **unlisted** (YouTube / Google Drive).
> Suggested length ~8–10 min (≈2 min/person). Narration can be Thai; keep technical terms + what's
> on screen in English. Each person records their own segment; one person stitches + uploads.
> **Everyone narrates their OWN part** (the instructor may do a Q&A — you must be able to explain it).

---

## 0:00 — Intro (whoever edits, ~40s)
- **Show:** `http://localhost:8080` home page of NoteVault.
- **Say:** "NoteVault เป็น note-sharing web app เขียนด้วย Python/Flask ทีม Jikko เป็น target project
  ของเรา — เราจะ attack มันแบบ attacker แล้ว fix แบบ defender. ทีมมี 4 คน แบ่งตาม vulnerability class:
  Injection, Auth/Crypto, Access Control, และ Supply Chain. ทุก build seed ด้วย `TEAM_ID=Jikko`
  marker `23dea5621f12`."

---

## PART A — Injection & Input (Supawan, 6631503042) — ~2:00

> Use your 6 stamped screenshots, or run live. Keep the identity stamp visible.

### A1 · SQL Injection → auth bypass (`/login`, CWE-89)  [~40s]
- **ATTACK — show:** terminal, run `curl.exe -i -s -X POST localhost:8080/login --data "username=admin'-- -" --data "password=wrong"`
  → **302 FOUND + Set-Cookie session** (`screenshots/1-before-login.png`).
- **Say:** "ผมใส่ username `admin'-- -` กับรหัสผ่านผิด แต่ได้ session ของ admin กลับมา — login ทะลุโดยไม่รู้รหัส."
- **ROOT CAUSE — show:** `app.py:128` before: `"... WHERE username = '%s' AND password = '%s'" % (...)`.
- **Say:** "เพราะ query เอา input มาต่อ string ตรง ๆ — เครื่องหมาย `'` ปิด literal แล้ว `-- -` comment
  ส่วนเช็ครหัสผ่านทิ้ง."
- **FIX — show:** the diff → parameterized `?` placeholders. Then run the same attack → **401 login failed**
  (`screenshots/4-after-login.png`).
- **Say:** "แก้เป็น parameterized query — input ถูก bind เป็น data ไม่ใช่ SQL. `admin'-- -` กลายเป็นชื่อ
  ที่ไม่ตรงใคร → 401."

### A2 · SQL Injection → credential dump (`/search`, CWE-89)  [~40s]
- **ATTACK — show:** `GET /search?q=%' UNION SELECT id,username,password FROM users-- -`
  → dumps `alice` / `admin` + MD5 hashes (`screenshots/2-before-search.png`).
- **Say:** "ด้วย UNION SELECT ผมดึง username กับ password hash ของทุกคนออกมาได้."
- **ROOT CAUSE — show:** `app.py:178` before: term concatenated into `LIKE '%...%'`.
- **FIX — show:** parameterized + `ESCAPE '\'` → run same payload → empty `<ul></ul>`
  (`screenshots/5-after-search.png`).
- **Say:** "bind ค่า + escape metacharacter ของ LIKE → UNION แทรกไม่ได้ ผลลัพธ์ว่าง."

### A3 · Command Injection → RCE as root (`/export`, CWE-78)  [~40s]
- **ATTACK — show:** `GET /export?fmt=txt;id` → `uid=0(root)` (`screenshots/3-before-export.png`).
- **Say:** "parameter `fmt` ต่อเข้า shell command — ผมใส่ `;id` แล้วรันคำสั่งได้ และได้ **root** เพราะ
  container รันเป็น root (ช่องโหว่ของ Supply Chain)."
- **ROOT CAUSE — show:** `app.py:202` before: `subprocess.run("echo ... " + fmt, shell=True)`.
- **FIX — show:** allowlist `{txt,csv,json}` + `shell=False` argv list → `?fmt=txt;id` → **400 invalid format**;
  `?fmt=csv` still works (`screenshots/6-after-export.png`).
- **Say:** "สองชั้น: allowlist ปฏิเสธค่านอกรายการ + ไม่ผ่าน shell เลย → metacharacter ไม่ถูกตีความ."
- **Transition:** "ข้อสังเกต — RCE ได้ root เพราะต่อกับช่องโหว่ container ของคน D. ส่งต่อให้คน B เรื่อง session."

---

## PART B — Auth / Session / Crypto (Person B) — ~2:00  *(B fills in)*
- JWT accepts `none` alg → forge admin token (CWE-347) · hardcoded secret (CWE-798) ·
  MD5 unsalted (CWE-327/916) · cookie missing HttpOnly/Secure (CWE-614).
- **attack → root cause (`app.py:83` etc.) → fix** (drop `none`, secret from env, bcrypt/argon2, cookie flags).

## PART C — Access Control & Output (Person C) — ~2:00  *(C fills in)*
- `/register` role injection → become admin (CWE-269) · IDOR `/api/notes/<id>` (CWE-639) ·
  `/admin` leaks hashes (CWE-200) · stored XSS via `|safe` (CWE-79) · `debug=True` (CWE-489).
- **attack → root cause → fix** (server-set role, ownership check, drop password column, autoescape, debug off).

## PART D — Supply Chain & Build/CI (Person D) — ~2:00  *(D fills in)*
- **Dependencies:** show old pins in `requirements.txt` → Trivy/pip-audit CVEs (CWE-1395).
- **Dockerfile:** runs as root, no digest pin, baked secret (CWE-250/798) → show hardened Dockerfile (non-root `USER`).
- **SBOM:** generate CycloneDX → show component count.
- **Cosign:** sign the artifact → paste `cosign verify` output.
- **CI pipeline:** show GitHub Actions run (Semgrep + Trivy + Gitleaks) **failing on a HIGH/CRITICAL**.

---

## Wrap-up (~40s)
- **Say:** "สรุป: เราเจอ ~16 ช่องโหว่ใน 3 ไฟล์, map กับ CWE + OWASP Top 10:2025, แก้แบบ minimal,
  ทำ SBOM + sign + CI gate. Residual risk ที่เหลือ: ... (เช่น rate-limiting, CSRF). Repo + รายงานฉบับเต็ม
  อยู่ตามลิงก์ในรายงาน."
- **Show:** final — all exploits failing on merged `main`.

---

## Recording checklist
- [ ] Identity stamp visible where evidence is shown (`whoami | ID | date`)
- [ ] Each person records their own segment
- [ ] Attack → root cause (show the vulnerable line) → fix (show the diff) → proof it fails
- [ ] Record on the **merged main** build, or note the branch
- [ ] Upload **unlisted**, "anyone with the link can view"
- [ ] Put the video link on the report **cover**
