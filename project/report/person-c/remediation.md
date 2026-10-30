# Findings และ Remediation — ส่วนคน C

เอกสารร่างสำหรับรวมรายงาน §4–5 ของทีม ข้อสรุปก่อนแก้มาจาก `project/starter-app/app.py` ณ commit `0edc2a3e01c9ac62a6e2c677b65f9a9085b2c45c` ระดับความรุนแรงเป็นการประเมินตามผลกระทบในแอปตัวอย่าง ไม่ใช่ CVSS ที่คำนวณแล้ว

ขั้นตอนทำซ้ำด้านล่างใช้เฉพาะแอป sandbox ของทีม บัญชี `alice/alicepw` และ `admin/admin123` เป็นข้อมูลตัวอย่างในโค้ดเดิม ควรใช้ฐานข้อมูลชั่วคราวแยกกันสำหรับก่อน/หลังแก้ เพราะการเริ่มแอปตาม starter จะลบข้อมูลเดิมแล้ว seed ใหม่

## F-C01 — ผู้สมัครกำหนดสิทธิ์และสวมตัวตนผ่านชื่อซ้ำได้

| รายการ | รายละเอียด |
|---|---|
| CWE | CWE-269 ตามการแบ่งงาน; CWE-266 อธิบาย incorrect privilege assignment ได้เฉพาะกว่า |
| OWASP | A01:2025 Broken Access Control |
| Severity | High: ผู้ไม่ล็อกอินสร้างบัญชีที่มีสิทธิ์ admin ได้ |
| จุดเกิด | `register()` และ schema `users` ใน `seed()` |
| สาเหตุ | เชื่อค่า `role` จาก client; อ้างอิงตัวตนด้วย username ที่ฐานข้อมูลอนุญาตให้ซ้ำ |

ทำซ้ำใน baseline: ส่ง `POST /register` แบบ form หรือ JSON โดยมี `username=c-review`, `password=testpw`, `role=admin` แล้วล็อกอินบัญชีนี้และเปิด `/admin` อีกกรณีคือสมัครชื่อ `admin` ด้วยรหัสผ่านใหม่ เมื่อ login ผ่าน แถวใหม่จะออก JWT ที่มี subject เป็น `admin` ขณะที่ `role_of()` คืน role ของบัญชีเดิม และโน้ตอ้าง owner ชื่อเดียวกัน การบังคับ role อย่างเดียวจึงไม่ปิดเส้นทางที่สอง

โค้ดก่อน/หลังส่วนหลัก:

```diff
- role = request.form.get("role") or (request.json or {}).get("role") or "user"
- ... (username, hashlib.md5(password.encode()).hexdigest(), role)
+ # Public registration cannot grant a privileged role.
+ ... (username, hashlib.md5(password.encode()).hexdigest(), "user")

- username TEXT, password TEXT, role TEXT
+ username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL
```

แพตช์ตรวจชนิดและค่าว่างของ username/password แล้วตอบ 400 เมื่อข้อมูลไม่ถูกต้อง รับข้อมูล form/JSON แยกกันอย่างชัดเจน และจับ `sqlite3.IntegrityError` เพื่อตอบ 409 เมื่อชื่อซ้ำ ข้อกำหนด UNIQUE ในฐานข้อมูลป้องกันชื่อซ้ำแม้เกิดคำขอพร้อมกัน

สิ่งที่ต้องยืนยันหลังแก้: สมัครพร้อม `role=admin` ได้บัญชี `user` ที่เข้า `/admin` แล้วถูกปฏิเสธ; สมัครชื่อ `alice`/`admin` ซ้ำได้ 409 โดยไม่เพิ่มบัญชี; สมัครชื่อใหม่ตามปกติได้ และ login ยังใช้งานได้ MD5 เดิมยังอยู่เพราะเป็นงานของ B

## F-C02 — อ่านโน้ตของผู้ใช้อื่นผ่าน IDOR/BOLA

| รายการ | รายละเอียด |
|---|---|
| CWE | CWE-639 Authorization Bypass Through User-Controlled Key |
| OWASP | A01:2025 Broken Access Control; API1:2023 BOLA |
| Severity | High: ผู้ใช้ทั่วไปอ่าน title/body/owner ของผู้อื่นได้ |
| จุดเกิด | `GET /api/notes/<int:nid>` |

ทำซ้ำใน baseline: ล็อกอินเป็น alice แล้วขอ `/api/notes/1` เพื่อดูโน้ตตัวเอง จากนั้นเปลี่ยนเป็น `/api/notes/2` และ `/api/notes/3` ซึ่ง seed ให้ admin เป็นเจ้าของ เดิมระบบตรวจเพียงว่ามี session แล้วส่งทั้งโน้ตของคนอื่นกลับมา รวมถึง team marker

```diff
- if not current_user():
+ user = current_user()
+ if not user:
      return jsonify(error="auth required"), 401
- r = con.execute("SELECT id,owner,title,body FROM notes WHERE id = ?", (nid,)).fetchone()
+ r = con.execute("SELECT id,owner,title,body FROM notes WHERE id = ? AND owner = ?",
+                 (nid, user)).fetchone()
```

การค้นหาผูกทั้ง `id` และ owner จาก session ฝั่งเซิร์ฟเวอร์ ใช้ policy เจ้าของเท่านั้น ไม่มีข้อยกเว้นให้ admin อ่านโน้ตผู้อื่นผ่าน endpoint นี้ ระบบตอบ 404 เหมือนกันทั้งเมื่อโน้ตไม่มีจริงและเมื่อเป็นของคนอื่น เพื่อลดการใช้คำตอบตรวจว่า ID นั้นมีอยู่หรือไม่ ผู้ไม่ล็อกอินยังได้ 401

สิ่งที่ต้องยืนยันหลังแก้: alice อ่าน `/api/notes/1` ได้ 200 แต่ `/api/notes/2`, `/api/notes/3` และ ID ที่ไม่มีจริงได้ 404 พร้อม body แบบเดียวกัน; admin อ่านโน้ตตนเองได้ แต่เปิดโน้ต alice ไม่ได้

## F-C03 — หน้า admin เปิดเผย password hash เกินหน้าที่

| รายการ | รายละเอียด |
|---|---|
| CWE | CWE-200 Exposure of Sensitive Information; CWE-201 อธิบายการส่งข้อมูลส่วนเกินเพิ่มได้ |
| OWASP | A01:2025 Broken Access Control |
| Severity | Medium: ต้องมีสิทธิ์ admin แต่ได้ credential material ของทุกบัญชีโดยไม่จำเป็น |
| จุดเกิด | `GET /admin` |

ทำซ้ำใน baseline: ล็อกอิน admin แล้วเปิด `/admin` ตรวจ JSON ว่ามี key `password` ซึ่งบรรจุ MD5 hash ของบัญชีแต่ละคน การรั่วนี้เพิ่มความเสี่ยง offline password guessing และรุนแรงขึ้นเมื่อเชื่อมกับ F-C01 แต่ไม่ควรรวมเงื่อนไข “admin แล้ว” กับ “ไม่ต้องล็อกอิน” เป็นข้ออ้างเดียวกัน

```diff
- rows = con.execute("SELECT id,username,password,role FROM users").fetchall()
+ rows = con.execute("SELECT id,username,role FROM users").fetchall()
```

เลือกคอลัมน์ที่อนุญาตให้เปิดเผยตั้งแต่ query ทำให้ password hash ไม่เข้า response object ตั้งแต่ต้น การตรวจ role เดิมยังคงใช้

สิ่งที่ต้องยืนยันหลังแก้: admin ได้ 200 และทุก object มีเฉพาะ `id`, `username`, `role`; ไม่มีค่า hash ใน response; alice และผู้ไม่ล็อกอินได้ 403 การแก้นี้ไม่ได้เปลี่ยนวิธีเก็บรหัสผ่านในฐานข้อมูล ซึ่งเป็นงานของ B

## F-C04 — Stored HTML/XSS และการประกอบ template จากเนื้อหาโน้ต

| รายการ | รายละเอียด |
|---|---|
| CWE | CWE-79; CWE-1336 เพิ่มสำหรับเส้นทาง SSTI ที่ search |
| OWASP | A05:2025 Injection |
| Severity | XSS: Medium ตามเส้นทางปกติที่แสดงโน้ตของตนเอง; SSTI: High เพราะ expression ทำงานบนเซิร์ฟเวอร์ |
| จุดเกิด | `PAGE`, `home()`, `search()` และ HTML output ของ `export()` |

ทำซ้ำใน baseline: ล็อกอิน alice แล้วเพิ่มโน้ตที่ title/body มี `<img src=x onerror=alert(1)>` เปิดหน้าแรกและค้นหาคำนั้น ตรวจทั้ง response HTML และการแสดงผลในเบราว์เซอร์ แยกอีกกรณีโดยบันทึก `{{7*7}}` ในโน้ต แล้วค้นหาให้โน้ตนั้นปรากฏ การแสดง `49` ใน baseline search ยืนยันว่าข้อมูลถูกตีความเป็น template expression; payload นี้ไม่รันคำสั่งระบบ

หน้าแรกเดิมต่อ HTML จาก title/body แล้วใช้ `|safe` ส่วน search เดิมนำ title/body ต่อเข้ากับ template source ก่อนเรียก Jinja จึงมีทั้งปัญหา HTML และ template injection การ escape ก่อนต่อเข้า template source อย่างเดียวไม่ใช่การแก้ SSTI ที่เหมาะสม เพราะอักขระ template ยังอาจมีความหมาย

หลักการก่อน/หลัง:

```diff
- <h3>Your notes</h3>{{ notes_html|safe }}
+ <h3>Your notes</h3><ul>
+ {% for note in notes %}
+ <li>#{{ note.id }} <b>{{ note.title }}</b>: {{ note.body }}</li>
+ {% endfor %}
+ </ul>

- render_template_string("<a href=/>back</a><ul>" + HTML_FROM_NOTE_VALUES + "</ul>")
+ render_template_string(SEARCH_PAGE, notes=rows)

- return "<pre>%s</pre>" % out.stdout
+ return render_template_string("<pre>{{ output }}</pre>", output=out.stdout)
```

ตัวอย่างด้านบนย่อเฉพาะแนวทาง ให้ใช้ `git show` ของ commit F-C04 เป็น diff ต้นฉบับจริงก่อนวางในรายงาน การใช้ template ที่กำหนดตายตัวและส่ง note values เป็นข้อมูลให้ autoescape จัดการ HTML ทำให้ Jinja ไม่ประมวลผล `{{7*7}}` ที่มาจากค่าข้อมูลอีกครั้ง

สิ่งที่ต้องยืนยันหลังแก้: title และ body ทั้งหน้าแรก/search มี `&lt;...&gt;` ใน HTML แทน element ที่ทำงาน; ข้อความ `{{7*7}}` แสดงเป็นข้อความเดิม และข้อมูลโน้ตธรรมดายังแสดงครบ การทดสอบ HTTP response ยืนยัน output encoding ได้ แต่หากรายงานอ้าง JavaScript execution ก่อนแก้ต้องมีหลักฐานเบราว์เซอร์จริง

ผลลัพธ์ `export()` เดิมใส่ stdout ลง HTML โดยตรง จึงแก้ให้ส่งเป็น template data เช่นกัน การทดสอบ output ใช้ mock subprocess จึงตรวจการ escape ได้โดยไม่รันคำสั่งจาก payload ส่วน command injection ใน `subprocess.run(..., shell=True)` ยังเป็นงานของ A

เส้นทางปกติให้ผู้สร้างดูโน้ตตัวเอง จึงยังไม่ควรอ้างว่ามี stored XSS ข้ามบัญชีโดยไม่มีเส้นทางส่ง payload ให้เหยื่อ ส่วน SQL injection ของ search ยังคงต้องให้ A แก้ แม้ C จะแก้วิธี render แล้ว

## F-C05 — เปิด debug ใน entry point ปกติ

| รายการ | รายละเอียด |
|---|---|
| CWE | CWE-489 Active Debug Code |
| OWASP | A02:2025 Security Misconfiguration |
| Severity | Medium; สูงขึ้นหาก debugger เปิดให้ผู้โจมตีเข้าถึง/ปลดล็อกได้จริง |
| จุดเกิด | บล็อก `if __name__ == "__main__"` |

หลักฐานก่อนแก้ที่ยืนยันได้จากโค้ดคือเรียก `app.run(..., debug=True)` ซึ่งเปิดความสามารถ debug ตามเส้นทางเริ่มนี้ ไม่ควรเขียนว่า “Werkzeug RCE สำเร็จ” จากค่า debug เพียงอย่างเดียว เพราะยังมีเงื่อนไขการเข้าถึงและ PIN

```diff
- app.run(host="0.0.0.0", port=8080, debug=True)
+ app.run(host="0.0.0.0", port=8080, debug=False, use_debugger=False, use_reloader=False)
```

แพตช์ตั้ง `debug=False` และปิด debugger/reloader ในการเริ่มแอป ทดสอบ entry point โดยจำลอง `Flask.run` เพื่อดูอาร์กิวเมนต์จริงโดยไม่เปิดพอร์ตรับการเชื่อมต่อหรือรัน `seed()` กับฐานข้อมูลประจำเครื่อง

สิ่งที่ต้องยืนยันหลังแก้: entry point ส่งค่าปิด debug/debugger/reloader ตามแพตช์ และหากเก็บหลักฐานการรันจริงให้เก็บ startup log ที่เห็น `Debug mode: off` ด้วย การปิด debug ไม่ได้เปลี่ยน development server ให้เป็น production server; การเลือก server/container และการเผยแพร่พอร์ตเป็นงานของ D

## หลักฐานทดสอบและ commit สำหรับรายงาน

ใช้ชุด [test_person_c.py](../../tests/test_person_c.py) เพื่อตรวจเงื่อนไขหลังแก้ในฐานข้อมูลชั่วคราว คำสั่งจาก root ของ repo:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/py312/bin/python -m unittest discover -s project/tests -p 'test_person_c.py' -v
```

คำสั่งนี้ใช้ environment ที่มีในเครื่องนี้ สำหรับเครื่องอื่นให้เตรียม Python 3.12 ตาม [README.md](README.md) แล้วใช้ interpreter ของ environment นั้น

ผลจริงใน [test-results.txt](test-results.txt) ทดสอบภายใต้ Python 3.12.15 กับ Flask 2.0.1, Werkzeug 2.0.1, Jinja2 3.0.1, PyJWT 1.7.1, requests 2.25.1 และ urllib3 1.26.4 โค้ดหลังแก้ผ่าน 17 tests ทั้งหมด (exit 0) ส่วน baseline ของ `main` ในพื้นที่ชั่วคราวไม่ผ่านชุดเดียวกัน (`failures=18, errors=13`; subtests ถูกนับแยก จึงไม่ใช่จำนวนช่องโหว่)

หลักฐานนี้ยืนยันการตอบกลับและเงื่อนไขที่ assert ในชุดทดสอบ Startup ใช้ mock `Flask.run` และ export ใช้ mock subprocess จึงไม่มีการรันคำสั่งจาก payload จริง ไม่มีเซิร์ฟเวอร์รับการเชื่อมต่อ และยังไม่มีผลจากเบราว์เซอร์หรือ Docker build ภาพที่ template รายงานกำหนดยังต้องเก็บจาก sandbox ของทีมตามจริง

อย่านำตัวอย่างผลที่คาดหวังด้านบนไปแปะเป็นผลที่รันจริง ให้บันทึกผลคำสั่งที่รันใน environment ของทีม และตรวจว่า dependency versions ตรงกับที่ระบุในรายงาน

Commit แพตช์ที่มีอยู่จริงบน branch:

| Finding | Commit |
|---|---|
| F-C01 | `574af26` — prevent registration privilege escalation |
| F-C02 | `2c5df1b` — enforce note ownership |
| F-C03 | `1e605be` — omit password hashes from admin output |
| F-C04 | `80cf57a` — escape output and separate template data |
| F-C05 | `af24b72` — disable debug and debugger |

ตรวจ hash และดู diff ของ commit จริงใน branch:

```bash
git log --oneline --grep='F-C'
git diff 0edc2a3e01c9ac62a6e2c677b65f9a9085b2c45c -- project/starter-app/app.py
```

ในรายงานแต่ละ finding ต้องมี hash จากประวัติจริงพร้อม diff และหลักฐานหลังแก้ ไม่ใช้ hash ของ baseline แทน commit แพตช์ ขณะรวม §5 ของทั้งทีมให้ตรวจ finding↔commit↔ภาพหลักฐานตรงกัน รวมถึงงานของ A/B/D ที่ยังไม่ได้อยู่ในเอกสารนี้

## ข้อจำกัดการสรุปผลทั้งทีม

- JWT `none` ใน allowlist ไม่ใช่หลักฐานว่า PyJWT 1.7.1 ยอมรับ token ไร้ลายเซ็น ต้องยืนยันกับรุ่น/ค่า key/ตัวตรวจจริงโดย B ก่อนอ้างเป็น finding
- ยังต้องแก้ SQL injection, command injection, secret, MD5, session/cookie และงาน supply chain ตามเจ้าของงานก่อนประเมินความเสี่ยงที่เหลือของแอปทั้งตัว
- แหล่งอ้างอิง OWASP 2025, CWE และ Flask ที่รองรับหมวด/แนวทางนี้อยู่ท้าย [README.md](README.md)
