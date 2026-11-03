# Demo Cue Card — Part A (Injection & Input) · Supawan 6631503042

**Target ~2:00.** Pattern每ข้อ = **ATTACK → ROOT CAUSE → FIX → PROOF**.
Narrate in Thai, keep terminal + code in English. Keep the identity stamp visible when showing evidence.
Have two things on screen ready: (1) a terminal, (2) `project/starter-app/app.py` open.

> You can demo **live** (before build + after build) or narrate over your 6 screenshots in
> `report/person-a/screenshots/`. Live is stronger; screenshots are the safe fallback.

---

## 0:00 — Intro ของ Part A (~10 วิ)
**[SAY]** "ผม Supawan รับผิดชอบ Injection & Input เจอ 3 ช่องโหว่ — SQL injection สองจุด กับ command
injection หนึ่งจุด เดี๋ยวโชว์ attack → สาเหตุ → วิธีแก้ ทีละอัน"

---

## 0:10 — F-01 SQLi /login → auth bypass (CWE-89)  (~30 วิ)
**[SHOW]** terminal — รัน:
```
curl.exe -i -s -X POST localhost:8080/login --data "username=admin'-- -" --data "password=wrong"
```
**[SAY attack]** "ผมใส่ username `admin'` ตามด้วย comment `-- -` รหัสผ่านผิด ๆ — แต่ได้ `302` กับ session
ของ admin กลับมา = login ทะลุโดยไม่รู้รหัส"
**[SHOW root cause]** เปิด `app.py` ชี้ `/login` เวอร์ชันเดิม: `"... WHERE username = '%s' ..." % (...)`
**[SAY]** "สาเหตุคือเอา input มาต่อ string เข้า SQL ตรง ๆ เครื่องหมาย `'` ปิด string, `-- -` comment
ส่วนเช็ครหัสทิ้ง"
**[SHOW fix]** ชี้โค้ดปัจจุบัน: `q = "... WHERE username = ? AND password = ?"` + `con.execute(q, (username, pw_hash))`
**[SAY fix]** "แก้เป็น parameterized query — input ถูก bind เป็น data ไม่ใช่ SQL"
**[SHOW proof]** รันคำสั่งเดิมอีกครั้ง → **`401 login failed`**
**[SAY]** "คราวนี้ `admin'-- -` เป็นชื่อธรรมดาที่ไม่ตรงใคร → 401 ✓"

---

## 0:40 — F-02 SQLi /search → ดึง password hash (CWE-89)  (~30 วิ)
**[SHOW]** login เป็น alice ก่อน แล้วรัน:
```
curl.exe -s -b cj.txt "localhost:8080/search?q=%25%27%20UNION%20SELECT%20id,username,password%20FROM%20users--%20-"
```
**[SAY attack]** "ใช้ `UNION SELECT` ดึง username กับ password hash ของทุกคน — เห็น alice กับ admin
พร้อม MD5 hash"
**[SHOW root cause]** `/search` เดิม: term ต่อเข้า `LIKE '%...%'`
**[SAY]** "input ต่อเข้า query โดยตรง เลย inject UNION ได้"
**[SHOW fix]** ชี้: parameterized `?` + `ESCAPE '\'` + escape `% _ \`
**[SAY fix]** "bind ค่า + escape metacharacter ของ LIKE → UNION แทรกไม่ได้"
**[SHOW proof]** รันเดิม → **`<ul></ul>` ว่าง**
**[SAY]** "ผลลัพธ์ว่าง ไม่มี hash หลุด ✓"

---

## 1:10 — F-03 Command injection /export → RCE as root (CWE-78)  (~35 วิ)
**[SHOW]** รัน:
```
curl.exe -s -b cj.txt "localhost:8080/export?fmt=txt;id"
```
**[SAY attack]** "parameter `fmt` ถูกส่งเข้า shell — ผมต่อ `;id` แล้วมันรันคำสั่ง `id` ให้ ได้
`uid=0(root)` = รันคำสั่งได้ และเป็น **root** เพราะ container รันเป็น root (ช่องโหว่ของคน D ที่มาเสริม)"
**[SHOW root cause]** `/export` เดิม: `subprocess.run("echo ... " + fmt, shell=True)`
**[SAY]** "`shell=True` + ต่อ string → `;` ถูก shell ตีความเป็นคำสั่งใหม่"
**[SHOW fix]** ชี้: `allowed = {"txt","csv","json"}` + `subprocess.run([...], shell=False)`
**[SAY fix]** "แก้สองชั้น — allowlist ปฏิเสธค่านอกรายการ และ `shell=False` ส่ง argument เป็น list
ไม่ผ่าน shell เลย metacharacter เลยไม่ถูกตีความ"
**[SHOW proof]** รันเดิม → **`400 invalid format`**; แล้วรัน `?fmt=csv` → ยังทำงานปกติ
**[SAY]** "`txt;id` โดนปฏิเสธ 400 แต่ `csv` ที่ถูกต้องยังใช้ได้ — แก้แบบไม่พังฟังก์ชัน ✓"

---

## 1:45 — ปิด Part A (~10 วิ)
**[SAY]** "สรุป injection 3 จุด แก้ด้วย parameterized query กับ shell=False — ทุก fix ผม verify ด้วยการ
รันจริง before/after ครับ ส่งต่อให้ [คน B] เรื่อง authentication"

---

## Pre-flight checklist (ก่อนกดอัด)
- [ ] Docker Desktop รันอยู่
- [ ] ตั้ง font terminal ใหญ่ (อ่านออกในวิดีโอ) — zoom in
- [ ] stamp พร้อม: `function stamp { "$(whoami) | 6631503042 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" }`
- [ ] โปรแกรมอัดจอ (OBS / Xbox Game Bar `Win+G`) พร้อม + ไมค์ทดสอบแล้ว
- [ ] ซ้อมพูด 1 รอบก่อนอัดจริง (ให้เข้า 2 นาที)
- [ ] ถ้าโชว์ live: เตรียม before build (vulnerable) ไว้สำหรับ ATTACK, after build (main) สำหรับ FIX
