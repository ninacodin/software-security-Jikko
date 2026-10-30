# งานคน C — Access Control & Output

Branch: `Bas/access-control-output`

เป้าหมาย: `project/starter-app/app.py`

โค้ดก่อนแก้: commit `0edc2a3e01c9ac62a6e2c677b65f9a9085b2c45c`

เอกสารนี้เป็นชุดส่งต่อให้ทีมสำหรับรายงาน §4–5 ไม่ใช่รายงานทั้งทีม ดูรายละเอียดก่อน/หลังใน [remediation.md](remediation.md) และใช้หัวข้อเดิมใน [REPORT-TEMPLATE.md](../../REPORT-TEMPLATE.md) ตอนรวมรายงาน รหัส `F-C01`–`F-C05` เป็นรหัสภายในส่วน C; เมื่อทีมเปลี่ยนเลข finding ต้องเปลี่ยนอ้างอิงในรายงานและตาราง commit ให้ตรงกัน

## ขอบเขตและข้อจำกัด

| Finding | หน้าที่คน C | หมวดที่แนะนำในรายงาน |
|---|---|---|
| F-C01 | บังคับ role ผู้สมัครใหม่ที่เซิร์ฟเวอร์ และป้องกัน username ซ้ำที่ทำให้สวมตัวตนบัญชีเดิมได้ | CWE-269 ตามการแบ่งงาน; ใช้ CWE-266 เพิ่มเพื่อระบุสาเหตุเฉพาะ, OWASP A01:2025 |
| F-C02 | ตรวจเจ้าของโน้ตก่อนส่งข้อมูลจาก `/api/notes/<nid>` | CWE-639, OWASP A01:2025; API1:2023 ใช้อธิบาย BOLA เพิ่มได้ |
| F-C03 | ส่งออกเฉพาะ `id`, `username`, `role` จาก `/admin` | CWE-200, OWASP A01:2025 |
| F-C04 | แสดง title/body และผล export เป็นข้อมูลใน template ที่ตายตัว ให้ autoescape ทำงาน | CWE-79, OWASP A05:2025; SSTI ที่พบร่วมกันใช้ CWE-1336 เพิ่ม |
| F-C05 | ปิด debug, debugger และ reloader ใน entry point ปกติ | CWE-489, OWASP A02:2025 |

การจับหมวด OWASP ในตารางเป็นการวิเคราะห์ตามพฤติกรรมของแอป ไม่ได้แปลว่าทุก CWE ปรากฏโดยตรงในรายการ mapped CWEs ของหมวดนั้น MITRE แนะนำให้เลือก CWE ที่เฉพาะเจาะจงกว่าหมวดกว้าง เช่น CWE-269 สำหรับรายงานช่องโหว่จริง

คน A ยังรับผิดชอบ SQL injection ที่ login/search และ command injection ที่ export; คน B รับผิดชอบ JWT, secret, password hashing และ cookie/session; คน D รับผิดชอบ dependencies, Docker, SBOM, signing และ CI การแก้ส่วน C อย่างเดียวจึงยังไม่ทำให้ NoteVault พร้อมใช้งานจริง

## ตรวจงานในเครื่อง

จาก root ของ repository ใช้ environment Python 3.12 ที่เตรียมไว้ในเครื่องนี้:

```bash
.venv/py312/bin/python -m unittest discover -s project/tests -p 'test_person_c.py' -v
```

สำหรับ checkout ใหม่ที่ยังไม่มี `.venv` และมี `python3.12` อยู่แล้ว เตรียม environment ตามนี้:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r project/starter-app/requirements.txt
.venv/bin/python -m unittest discover -s project/tests -p 'test_person_c.py' -v
```

เลือก Python 3.12 ให้ตรงรุ่นหลัก/รองกับ Dockerfile เดิม การใช้ Python 3.14 กับ dependency เก่าที่โปรเจกต์ตรึงไว้อาจล้มตั้งแต่ import เช่น Werkzeug 2.0.1 เรียก `ast.Str` ที่ถูกถอดออก จึงไม่ควรตีความ import error นั้นว่าเป็นผลของแพตช์ส่วน C

อ่านชื่อกรณีทดสอบและผลจริงที่แสดงก่อนนำไปอ้างในรายงาน การผ่านชุดทดสอบเป็นหลักฐานสำหรับเงื่อนไขที่ตรวจเท่านั้น ไม่ใช่การยืนยันว่าไม่เหลือช่องโหว่ทั้งแอป

ผลที่รันจริงบันทึกใน [test-results.txt](test-results.txt): Python 3.12.15 และ dependency ทั้ง 6 ตัวตาม `requirements.txt` เดิม โค้ดหลังแก้ผ่าน **17/17 tests** (exit 0) ส่วนโค้ด baseline ที่อ่านจาก `main` และทดสอบด้วยชุดเดียวกันในพื้นที่ชั่วคราวไม่ผ่าน โดยรายงาน `failures=18, errors=13` ซึ่งนับ subtests แยกด้วย จึงไม่ใช่จำนวนช่องโหว่ 31 ข้อ

การทดสอบนี้ใช้ฐานข้อมูลชั่วคราวและ Flask test client โดย mock การเริ่มเซิร์ฟเวอร์กับ subprocess ของ export จึงไม่มีการเปิดพอร์ตหรือรัน shell payload จริง ยังไม่มีภาพเบราว์เซอร์หรือผล Docker build ให้ใช้อ้างเป็นหลักฐานสองอย่างนั้น

เมื่อต้องเก็บภาพหรือ request/response สำหรับส่งงาน ให้รันเฉพาะ sandbox ในเครื่อง ตั้ง `TEAM_ID` เป็นค่าที่ทีมตกลงก่อนเริ่มแอป และเก็บหลักฐานจริงพร้อมวันเวลา/branch/commit ที่ทดสอบ ฐานข้อมูลตัวอย่างถูกสร้างใหม่โดย `seed()` เมื่อเริ่มด้วย `python app.py`; อย่าใช้ฐานข้อมูลที่ต้องการเก็บไว้กับ entry point นี้

## การรวมกับงานเพื่อน

1. ให้ทีมตรวจ diff บน branch นี้ โดยเฉพาะ `register()`, `seed()`, `api_note()`, `home()`, `search()`, `admin()` และส่วนเริ่มแอป
2. เมื่อรวมกับ A ให้เก็บการแก้ SQL ของ `search()` พร้อมการ render แบบใหม่ของ C ทั้งสองอย่างต้องอยู่พร้อมกัน
3. เมื่อรวมกับ B ให้เก็บการบังคับ role/username ไม่ซ้ำพร้อม password hashing แบบใหม่ อย่าแทนที่ `register()` ทั้งก้อนจนทำให้ส่วนใดส่วนหนึ่งหาย
4. หลังรวมทุก branch ให้รันทดสอบอีกครั้ง แล้วให้ D ตรวจการเริ่มแอปจริงและ CI ของโค้ดที่รวมแล้ว

Username เป็นตัวอ้างอิงเจ้าของโน้ตและ JWT subject อยู่ในสถาปัตยกรรมปัจจุบัน จึงต้องไม่ซ้ำตั้งแต่ฐานข้อมูล การเปลี่ยน schema ใน `seed()` ใช้กับฐานข้อมูลที่สร้างใหม่ หากใช้ฐานข้อมูลเดิมผ่าน WSGI ต้องตรวจบัญชีซ้ำและย้าย schema โดยแผน migration ของทีมก่อน; การเปลี่ยน `seed()` ไม่ได้ย้ายข้อมูลเดิมให้อัตโนมัติ

## งานรายงาน §5 และ Git

- นำข้อความ/ตัวอย่างก่อน–หลังจาก [remediation.md](remediation.md) ไปประกอบรายงานหลัก เติม commit จริงและแนบภาพทดสอบของทีมตาม template
- ดึง commit ที่อ้าง finding ได้ด้วย `git log --oneline --grep='F-C'`; ดู diff จริงด้วย `git show <commit>` ก่อนใส่รายงาน
- เก็บจำนวนช่องโหว่และระดับความรุนแรงหลังรวมงานทั้งทีม ไม่รวม SSTI เป็นอีก finding ซ้ำถ้าทีมเลือกนับเป็นผลกระทบร่วมของ F-C04
- เปิดเผยการใช้ AI ตามจริง เช่น “ใช้ Codex ช่วยตรวจโค้ดส่วน C เสนอและจัดทำแพตช์/การทดสอบ/ร่างเอกสาร สมาชิกตรวจสอบผลและอธิบายการแก้ด้วยตนเอง” ปรับข้อความให้ตรงกับสิ่งที่ทำจริง

## แหล่งอ้างอิงหลัก

- [OWASP A01:2025 — Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/)
- [OWASP A02:2025 — Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/)
- [OWASP A05:2025 — Injection](https://top10.owasp.org/2025/A05_2025-Injection/)
- MITRE: [CWE-269](https://cwe.mitre.org/data/definitions/269.html), [CWE-266](https://cwe.mitre.org/data/definitions/266.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html), [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html), [CWE-489](https://cwe.mitre.org/data/definitions/489.html)
- Flask: [การทำ autoescape ของ template](https://flask.palletsprojects.com/en/stable/templating/), [debugger และความเสี่ยง](https://flask.palletsprojects.com/en/stable/debugging/)

## หลักฐานภาพฉบับปัจจุบัน

ใช้ชุด [Playwright ก่อน–หลัง 16 ภาพ](before-after/README.md) ใน [REVIEW.md](REVIEW.md) แทนชุดภาพที่แคปเองเดิม ภาพใหม่ใช้ `TEAM_ID=Jikko` พร้อม timestamp และมีคำอธิบายข้อจำกัดเรื่องภาพ terminal อยู่ในภาคผนวก
