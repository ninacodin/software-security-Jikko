# NoteVault Security Review
## Part C: Access Control and Output Handling

| Item | Details |
|---|---|
| Contributor | Bas — Part C |
| Report date | 23 October 2026 |
| Browser evidence added | 30 October 2026 |
| Repository | [ninacodin/software-security-Jikko](https://github.com/ninacodin/software-security-Jikko) |
| Branch | `Bas/access-control-output` |
| Modified file | `project/starter-app/app.py` |
| Baseline commit | `0edc2a3e01c9ac62a6e2c677b65f9a9085b2c45c` |
| Reviewed commit after fixes | `1662fc98cbc33c49c4252719bd5b9ef0c8350346` |

This report covers the findings, fixes, and test results for Part C of the NoteVault project. It provides material for the Vulnerability Findings and Remediation sections of the team report. The code review and automated results describe the Part C changes. The browser evidence captured on 30 October 2026 uses Playwright against isolated before-and-after snapshots seeded with TEAM_ID=Jikko. It is identified separately from the earlier automated test run.

## 1. Objective and Scope

The review focused on how NoteVault assigns user roles, checks note ownership, returns account information, and displays user input. It also covered the debug settings used when starting the application.

The changes affected `register()`, `seed()`, `api_note()`, `admin()`, `home()`, `search()`, the output of `export()`, and the application startup code. SQL injection, shell command execution, JWT handling, password hashing, and build security remain assigned to the other team members.

## 2. Findings and Fixes

### 2.1 F-C01 — Users Could Choose Their Own Role During Registration

**Location:** `register()` and the `users` table in `seed()`  
**Classification:** CWE-269; CWE-266 describes the incorrect assignment of privileges more specifically.

The original registration function accepted the `role` value from the request and stored it directly. A person registering an account could submit `role=admin`, even though the registration form did not provide a role field.

The database also allowed duplicate usernames. This was a separate access control problem because the application used the username to identify the account in JWTs, role checks, and note ownership. Two accounts with the same username could therefore be treated as the same identity.

The updated function assigns the `user` role on the server and ignores any role supplied by the client. It checks that the username and password are valid, non-empty strings. The table definition now requires unique usernames and prevents null values in the account fields. Duplicate registration returns HTTP 409, while invalid registration data returns HTTP 400.

```diff
- (username, hashlib.md5(password.encode()).hexdigest(), role)
+ (username, hashlib.md5(password.encode()).hexdigest(), "user")

- username TEXT, password TEXT, role TEXT
+ username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL
```

**Test result:** Registration requests containing `role=admin`, sent as either form data or JSON, created regular users. These users received HTTP 403 when requesting `/admin`. Duplicate registrations using `alice` or `admin` were rejected. Registration and login with a new username still worked.

#### Playwright before-and-after evidence

**Role assignment — before**

![Role assignment before](before-after/registration-before.png)

The request supplied `role=admin` when creating `c-evidence`. The new account could open `/admin` with HTTP 200, showing that the server accepted a privileged role chosen by the client.

**Role assignment — after**

![Role assignment after](before-after/registration-after.png)

The same registration request created a regular-user account. Its request to `/admin` returned HTTP 403. The right-hand panel records the submitted role and actual response status.

**Duplicate registration — before**

![Duplicate registration before](before-after/duplicate-before.png)

Registering the existing username `alice` returned HTTP 302, so the duplicate registration was accepted. The POST result is recorded in the panel; the home page on the left is context rather than the POST response.

**Duplicate registration — after**

![Duplicate registration after](before-after/duplicate-after.png)

The same duplicate username returned HTTP 409 with `username already exists`. This prevents a second account from using an existing identity.

The [evidence appendix](before-after/README.md) explains the captured results, source commits, timestamps, and limitations of these images.

**Fix commit:** [`574af26`](https://github.com/ninacodin/software-security-Jikko/commit/574af26)

### 2.2 F-C02 — Note Access Did Not Check Ownership

**Location:** `GET /api/notes/<int:nid>`  
**Classification:** IDOR/BOLA — CWE-639

The original endpoint checked whether the requester was logged in, then selected a note using only its ID. It did not check whether the note belonged to that user. A logged-in user could change the ID in the URL to request another user's note.

The query now checks both the note ID and the owner. The owner value comes from the identity returned by the application's session verification function, rather than a request parameter.

```diff
- SELECT id,owner,title,body FROM notes WHERE id = ?
+ SELECT id,owner,title,body FROM notes WHERE id = ? AND owner = ?
```

**Test result:** Owners could read their own notes with HTTP 200. Requests without a valid session returned HTTP 401. Requests for another user's note and requests for a nonexistent ID both returned HTTP 404 with the same response body. This endpoint follows an owner-only policy, including for administrator accounts.

#### Playwright before-and-after evidence

**Note ownership — before**

![Note ownership before](before-after/ownership-before.png)

While logged in as `alice`, requesting `/api/notes/2` returned HTTP 200 and disclosed the administrator's note. The panel also records successful access to alice's own note as a control case.

**Note ownership — after**

![Note ownership after](before-after/ownership-after.png)

Alice could still read her own note, but requesting the administrator's note returned HTTP 404 with `not found`. The query now checks both the note ID and its owner.

The [evidence appendix](before-after/README.md) explains the captured results, source commits, timestamps, and limitations of these images.

**Fix commit:** [`2c5df1b`](https://github.com/ninacodin/software-security-Jikko/commit/2c5df1b)

### 2.3 F-C03 — The Admin Endpoint Exposed Password Hashes

**Location:** `GET /admin`  
**Classification:** Sensitive information exposure — CWE-200

The original query selected the `password` column along with the account details and returned it in the JSON response. Although the endpoint required administrator access, password hashes were unnecessary for displaying a user list. Returning them also increased the impact of a compromised administrator account.

The query was changed to select only the fields needed for the user list.

```diff
- SELECT id,username,password,role FROM users
+ SELECT id,username,role FROM users
```

**Test result:** Administrators could still view the user list. Each account object contained only `id`, `username`, and `role`. The response did not contain a `password` field or the seeded password hashes. Regular users and visitors without a session still received HTTP 403.

#### Playwright before-and-after evidence

**Admin response fields — before**

![Admin response fields before](before-after/admin-before.png)

The administrator's account-list response included a `password` field with a hash for each account. These values were unnecessary for viewing account information.

**Admin response fields — after**

![Admin response fields after](before-after/admin-after.png)

The account-list response contains only `id`, `username`, and `role`. Removing the password column from the query prevents hashes from entering the response.

The [evidence appendix](before-after/README.md) explains the captured results, source commits, timestamps, and limitations of these images.

**Fix commit:** [`1e605be`](https://github.com/ninacodin/software-security-Jikko/commit/1e605be)

### 2.4 F-C04 — User Input Was Included Directly in HTML and Templates

**Location:** `PAGE`, `home()`, `search()`, and the output of `export()`  
**Classification:** XSS — CWE-79; template injection — CWE-1336

The home page originally built HTML using note titles and bodies, then displayed it with the `safe` filter. This allowed note content to become HTML markup. The search page had an additional problem: it inserted note content into the template source before Jinja processed it. As a result, text saved in a note could be interpreted as a template expression.

The updated pages use fixed templates and pass note content as data. Jinja loops display the notes, and autoescaping handles the values. The export response also passes its output as a template variable.

```diff
- {{ notes_html|safe }}
+ {% for note in notes %}
+ <li>#{{ note.id }} <b>{{ note.title }}</b>: {{ note.body }}</li>
+ {% endfor %}

- render_template_string(HTML_FROM_NOTE_VALUES)
+ render_template_string(SEARCH_PAGE, notes=rows)

- return "<pre>%s</pre>" % out.stdout
+ return render_template_string("<pre>{{ output }}</pre>", output=out.stdout)
```

These excerpts show the main changes. The full patch is available in the linked commit.

**Test result:** Note content containing `<script>` and `<img>` tags was escaped in the home and search responses. The text `{{7*7}}` remained unchanged instead of being evaluated as `49`. Export output was also escaped. The export test used mocked subprocess output and did not execute a shell payload.

The tests confirm output encoding and separation of data from template source. The automated tests and browser figures do not establish cross-user XSS or demonstrate successful JavaScript execution. In the normal interface, users view their own notes, so any claim about an effect on another user requires further evidence.

#### Playwright before-and-after evidence

**Stored HTML and JavaScript — before**

![Stored HTML and JavaScript before](before-after/xss-before.png)

The stored HTML payload was interpreted by the browser. Playwright recorded actual `C04` JavaScript dialog messages and dismissed them to continue the capture. The panel preserves those observations; a repeated render can trigger the same payload more than once.

**Stored HTML and JavaScript — after**

![Stored HTML and JavaScript after](before-after/xss-after.png)

The same title and body are displayed as literal tag text. No JavaScript dialogs were observed in the checked flow. This supports the output-escaping change without claiming that every possible XSS payload was tested.

**Stored template expression — before**

![Stored template expression before](before-after/template-before.png)

The stored body `check {{7*7}}` appeared as `check 49` in search results. The application had treated note content as part of the Jinja template source.

**Stored template expression — after**

![Stored template expression after](before-after/template-after.png)

Search results retain `check {{7*7}}` exactly. Passing note values into a fixed template keeps the expression as data rather than evaluating it.

The [evidence appendix](before-after/README.md) explains the captured results, source commits, timestamps, and limitations of these images.

**Fix commit:** [`80cf57a`](https://github.com/ninacodin/software-security-Jikko/commit/80cf57a)

### 2.5 F-C05 — Debug Mode Was Enabled at Startup

**Location:** The `if __name__ == "__main__"` block  
**Classification:** Active Debug Code — CWE-489

The application originally started with `debug=True`. This setting may expose internal error details and debugger features when the application is run outside a development environment. However, the setting alone does not prove that an attacker can execute commands through the debugger.

The startup call now explicitly disables debug mode, the debugger, and the reloader.

```diff
- app.run(host="0.0.0.0", port=8080, debug=True)
+ app.run(host="0.0.0.0", port=8080, debug=False,
+         use_debugger=False, use_reloader=False)
```

**Test result:** The test confirmed that the startup code passed all three disabling options, including when `FLASK_DEBUG=1` was set. It mocked `Flask.run` to avoid starting a server. This result covers the modified entry point. Starting the application through Flask CLI or a separate deployment configuration requires its own checks.

#### Playwright before-and-after evidence

**Startup configuration — before**

![Startup configuration before](before-after/debug-before.png)

The configuration check captured `debug=True` from the original entry point by mocking `Flask.run`. This is a startup-configuration test, not an exposed interactive debugger.

**Startup configuration — after**

![Startup configuration after](before-after/debug-after.png)

The same configuration check captured `debug=False`, `use_debugger=False`, and `use_reloader=False`. Both evidence servers were themselves run without debug mode for safe local capture.

The [evidence appendix](before-after/README.md) explains the captured results, source commits, timestamps, and limitations of these images.

**Fix commit:** [`af24b72`](https://github.com/ninacodin/software-security-Jikko/commit/af24b72)

## 3. Test Method and Results

The recorded tests used Python 3.12.15 with Flask 2.0.1, Werkzeug 2.0.1, Jinja2 3.0.1, and PyJWT 1.7.1. Flask's test client handled the requests. Each test used a temporary database, keeping the test data separate from the database used for manual browsing.

The following command runs the tests in the environment prepared on this machine:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/py312/bin/python -m unittest discover -s project/tests -p 'test_person_c.py' -v
```

| Test group | Test methods | Result after fixes |
|---|---:|---|
| Registration, role assignment, duplicate usernames, and invalid input | 7 | Passed |
| Note access and ownership | 4 | Passed |
| Admin access and response fields | 2 | Passed |
| Note rendering and export output | 3 | Passed |
| Debug settings at the entry point | 1 | Passed |
| **Total** | **17** | **All passed** |

The saved [test log](test-results.txt) records 17 passing tests with exit code 0 for the fixed code. The same suite was run against the baseline source from `main` in a temporary directory. That run reported `failures=18, errors=13`. These counts include subtests and should not be interpreted as separate vulnerabilities or separate test methods.

The suite checks normal use as well as rejected requests. This helps confirm that users can still register and log in, owners can read their notes, and administrators can view the user list after the fixes.

### 3.1 Before-and-After Browser Evidence

A separate controlled capture compares the original baseline with the integrated main version at commit `b1a977dc5100a423ba9953d94465cce40d4c6914`. Both databases were newly seeded with `TEAM_ID=Jikko`. Playwright captured 16 screenshots in eight pairs: team identity, role assignment, duplicate registration, note ownership, admin response fields, XSS, template evaluation, and startup configuration.

[Open the complete before-and-after figures and explanations](before-after/README.md). Each pair includes the observed result and capture time. The [capture manifest](before-after/manifest.json) records source commits, actual request results and screenshot checksums. Student ID `6631503106` identifies the tester; it is separate from the team identifier.

| Check | Before | After |
|---|---|---|
| Team identity | Seeded as Jikko | Seeded as Jikko |
| Registration with role=admin | Admin endpoint accessible, HTTP 200 | Regular-user account, HTTP 403 |
| Duplicate username | Accepted, HTTP 302 | Rejected, HTTP 409 |
| Reading another owner's note | Note returned, HTTP 200 | Not found, HTTP 404 |
| Admin user list | Password hashes included | Password fields omitted |
| Stored HTML payload | JavaScript dialogs recorded | Literal text; no dialogs in the checked flow |
| Stored template expression | Evaluated as 49 | Preserved as {{7*7}} |
| Startup configuration | debug=True | Debugger and reloader explicitly disabled |

The timestamps and command output were generated during capture, not added to finished images. The execution panel is a browser-rendered record, not an OS terminal. A full desktop capture with a real terminal is still needed to meet the course's exact evidence format. The debug pair records the source entry point with Flask.run mocked; both capture servers themselves used debug=False. The after version includes other team members' fixes and should not be presented as an isolated test of Part C alone.

## 4. Limitations and Integration

The unique username constraint was added to the schema in `seed()`, so it applies to newly created databases. An existing database needs a migration and a check for duplicate accounts. Updating the source code alone does not change its schema.

When merging Part A, the team must retain both the SQL fixes and the updated rendering in `search()`. The command execution fix and output escaping in `export()` must also be kept together. When merging Part B, the updated password hashing must preserve server-side role assignment and unique usernames.

The recorded unit tests do not provide evidence of a Docker build. The browser figures document only the manual cases shown and do not replace a complete browser test. Final submission evidence still requires the tester's identity and timestamp as specified by the course. Application tests and build checks should be repeated after all branches are merged.

## 5. Discussion

The changes address three related issues: who can receive a privilege, who can access a particular note, and what information the application returns. Fixed templates also prevent note content from becoming part of the template source.

The duplicate username issue shows why changing a single role field was not enough. Since several parts of the application identify users by username, that value must distinguish one account from another. The database constraint supports the access checks made by the application.

The test results support the fixes within Part C's scope. A final assessment of NoteVault still depends on the combined code, especially the SQL injection, command execution, and session handling changes that affect the trustworthiness of a requester's identity.

## 6. References and Evidence

- [Course report template](../../REPORT-TEMPLATE.md)
- [Detailed Part C remediation notes](remediation.md)
- [Part C regression tests](../../tests/test_person_c.py)
- [Recorded baseline and fixed-code test results](test-results.txt)
- [MITRE CWE-266: Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)
- [MITRE CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [MITRE CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [MITRE CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html)
- [MITRE CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
