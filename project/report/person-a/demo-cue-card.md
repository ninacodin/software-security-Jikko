# Demo Cue Card — Part 1 (Threat Model + Injection) · Supawan 6631503042

**Target ~2:30. English, simple and slow.** Pattern for each finding = **ATTACK → ROOT CAUSE → FIX → PROOF**.
Keep the identity stamp visible when you show evidence.
On screen, have ready: (1) a terminal, (2) `project/starter-app/app.py`, (3) the DFD image.

> `stamp` = `whoami | 6631503042 | date`. Old vulnerable build on **:8081**, fixed build on **:8080**.

---

## 0:00 — Threat model (~45s)
**[SHOW]** the DFD (`notevault-dfd.svg`).
**[SAY]** "Hi, I am Supawan. NoteVault is a small Flask web app. Users send requests from the
internet to the app. The app reads and writes a SQLite database, and it also runs an OS command to
export notes."
**[SAY]** "I drew the data-flow diagram and marked three trust boundaries: the network, the SQL
boundary, and the shell boundary. I used STRIDE to find threats. My top risks are all **Tampering**
and **Information Disclosure** through user input — two SQL injections and one command injection. I
fixed all three. Let me show each one."

---

## 0:45 — F-01 · SQL injection in /login → login bypass (CWE-89) (~35s)
**[SHOW terminal]**
```
curl.exe -i -s -X POST localhost:8081/login --data "username=admin'-- -" --data "password=wrong"
```
**[SAY attack]** "I send the username `admin'` and a comment `-- -`. The password is wrong. But I get
`302` and an admin session. I am logged in as admin without the password."
**[SHOW code]** old `/login`: `"... WHERE username = '%s' ..." % (...)`
**[SAY cause]** "The old code puts my input straight into the SQL text. My quote ends the string, and
the comment removes the password check."
**[SHOW code]** fix: `con.execute("... WHERE username = ? AND password = ?", (username, pw_hash))`
**[SAY fix]** "The fix uses a parameterized query. The input is now data, not SQL."
**[SHOW proof]** same command on `:8080` → **`401 login failed`**.
**[SAY]** "Now `admin'-- -` is just a name that matches nobody. The attack is blocked."

---

## 1:20 — F-02 · SQL injection in /search → password dump (CWE-89) (~30s)
**[SHOW]** (logged in as alice) run:
```
curl.exe -s -b cj.txt "localhost:8081/search?q=%25%27%20UNION%20SELECT%20id,username,password%20FROM%20users--%20-"
```
**[SAY attack]** "I use `UNION SELECT` to read every user's name and password hash. I can see alice and
admin with their MD5 hashes."
**[SHOW code]** old `/search`: the search term is joined into `LIKE '%...%'`.
**[SAY cause]** "Again, the input goes straight into the query, so I can inject `UNION`."
**[SHOW code]** fix: parameterized `?` + `ESCAPE '\'` and escape `% _ \`.
**[SAY fix]** "The value is bound as data, and the LIKE special characters are escaped. `UNION` cannot
get in."
**[SHOW proof]** same payload on `:8080` → **empty `<ul></ul>`**.
**[SAY]** "The result is empty. No hash leaks."

---

## 1:50 — F-03 · Command injection in /export → RCE as root (CWE-78) (~35s)
**[SHOW]** run:
```
curl.exe -s -b cj.txt "localhost:8081/export?fmt=txt;id"
```
**[SAY attack]** "The `fmt` value goes into a shell command. I add `;id`, and the server runs `id` for
me. I get `uid=0(root)` — I can run commands, and as **root**, because the container runs as root
(that is Sadayu's supply-chain finding)."
**[SHOW code]** old `/export`: `subprocess.run("echo ... " + fmt, shell=True)`
**[SAY cause]** "`shell=True` plus string joining means the `;` starts a new command."
**[SHOW code]** fix: `allowed = {"txt","csv","json"}` + `subprocess.run([...], shell=False)`
**[SAY fix]** "Two layers: an allowlist rejects any other value, and `shell=False` passes the argument
as a list, so the shell never sees it."
**[SHOW proof]** `?fmt=txt;id` on `:8080` → **`400 invalid format`**; `?fmt=csv` → still works.
**[SAY]** "The attack is rejected, but the real feature still works."

---

## 2:25 — Handoff (~5s)
**[SAY]** "So: three injection points, fixed with parameterized queries and `shell=False`. I verified
every fix by running the before and after. Next, Phuriphat will cover authentication."

---

## Pre-flight checklist (before you record)
- [ ] Docker Desktop running; **:8081** = old build, **:8080** = fixed build
- [ ] Terminal font large (zoom in so text is readable in the video)
- [ ] `stamp` ready: `function stamp { "$(whoami) | 6631503042 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" }`
- [ ] Screen recorder (OBS / `Win+G`) + mic tested
- [ ] Rehearse once out loud and time it (aim for 2:30)
- [ ] For F-02: log in as alice on `:8081` first (save cookie to `cj.txt`); use a separate window for `:8080`
