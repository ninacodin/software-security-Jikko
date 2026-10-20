# Person A — Before/After Exploit Verification (reproduced by running)

Target: NoteVault `project/starter-app`, TEAM_ID=Jikko. Owner: Supawan 6631503042.
BEFORE = commit `039029f` (import, vulnerable) · AFTER = commit `d66e777` (fix, branch fix/injection-input-6631503042).
Reproduced live with Docker (server 29.2.0) + curl.exe on 2026-10-20.

> NOTE: these are the raw tool outputs. For the report's "Evidence" cells you still need the
> **screenshots with your identity stamp in frame**:
>   printf '%s | %s | ' "$(whoami)" '6631503042'; date '+%F %T %Z'

---

## F-A1 — SQLi /login (auth bypass)
Request: `POST /login  username=admin'-- -  password=wrong`

BEFORE:
```
HTTP/1.0 302 FOUND
Set-Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbictLSAtIn0...; Path=/
```
AFTER:
```
HTTP/1.0 401 UNAUTHORIZED
login failed
```
Verdict: auth bypass CLOSED (302+session → 401).

---

## F-A2 — SQLi /search (UNION credential dump)
Request: authenticated `GET /search?q=%' UNION SELECT id,username,password FROM users-- -`

BEFORE:
```
<a href=/>back</a><ul><li>alice: 15da1f78ad7d474862865bab1aab4d51</li><li>groceries: milk, eggs</li><li>admin: 0192023a7bbd73250516f069df18b500</li></ul>
```
(leaked MD5 password hashes for alice + admin)

AFTER:
```
<a href=/>back</a><ul></ul>
```
Verdict: credential disclosure CLOSED (hashes → empty result).

---

## F-A3 — Command injection /export (RCE as root)
Request: authenticated `GET /export?fmt=txt;id`

BEFORE:
```
<pre>exporting notes as txt
uid=0(root) gid=0(root) groups=0(root)
</pre>
```
AFTER:
```
HTTP/1.0 400 BAD REQUEST
invalid format
```
Functional sanity (AFTER) — valid format still works, `GET /export?fmt=csv`:
```
<pre>exporting notes as csv
</pre>
```
Verdict: command injection CLOSED (uid=0 root → 400); legitimate export preserved.
