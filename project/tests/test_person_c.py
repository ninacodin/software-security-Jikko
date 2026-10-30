"""Person C security regressions. All writes use disposable test databases.

Run from the repository root:
    python -m unittest discover -s project/tests -p 'test_person_c.py' -v
"""

import importlib.util
import os
from pathlib import Path
import runpy
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from flask import Flask


APP_PATH = Path(__file__).resolve().parents[1] / "starter-app" / "app.py"
SPEC = importlib.util.spec_from_file_location("notevault_person_c", APP_PATH)
notevault = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = notevault
SPEC.loader.exec_module(notevault)


class PersonCSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="notevault-person-c-")
        self.addCleanup(self.temp_dir.cleanup)
        self.original_db = notevault.DB
        self.addCleanup(setattr, notevault, "DB", self.original_db)
        notevault.DB = str(Path(self.temp_dir.name) / "notes.db")
        notevault.app.config.update(TESTING=True)
        notevault.seed()
        self.client = notevault.app.test_client()

    def login(self, username="alice", password="alicepw", client=None):
        response = (client or self.client).post(
            "/login", data={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))

    def test_json_registration_cannot_assign_admin_role(self):
        response = self.client.post(
            "/register",
            json={"username": "json-user", "password": "test-password", "role": "admin"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(notevault.role_of("json-user"), "user")
        self.login("json-user", "test-password")
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_form_registration_cannot_assign_admin_role(self):
        response = self.client.post(
            "/register",
            data={"username": "form-user", "password": "test-password", "role": "admin"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(notevault.role_of("form-user"), "user")
        self.login("form-user", "test-password")
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_normal_registration_and_login_still_work(self):
        response = self.client.post(
            "/register", data={"username": "new-user", "password": "new-password"}
        )
        self.assertEqual(response.status_code, 302)
        self.login("new-user", "new-password")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_duplicate_seeded_names_cannot_take_over_existing_accounts(self):
        for username, original_password, expected_role in (
            ("admin", "admin123", "admin"),
            ("alice", "alicepw", "user"),
        ):
            with self.subTest(username=username):
                client = notevault.app.test_client()
                response = client.post(
                    "/register",
                    json={"username": username, "password": "attacker-password", "role": "admin"},
                )
                self.assertEqual(response.status_code, 409)
                self.assertEqual(notevault.role_of(username), expected_role)
                failed_login = client.post(
                    "/login", data={"username": username, "password": "attacker-password"}
                )
                self.assertEqual(failed_login.status_code, 401)
                self.login(username, original_password, client=client)

    def test_database_rejects_duplicate_username(self):
        con = notevault.db()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    "INSERT INTO users (username,password,role) VALUES (?,?,?)",
                    ("alice", "irrelevant-hash", "user"),
                )
        finally:
            con.close()

    def test_invalid_registration_fields_return_400(self):
        payloads = [
            {},
            {"username": "missing-password"},
            {"password": "missing-username"},
            {"username": "", "password": "password"},
            {"username": "   ", "password": "password"},
            {"username": "empty-password", "password": ""},
            {"username": None, "password": "password"},
            {"username": 123, "password": "password"},
            {"username": ["alice"], "password": "password"},
            {"username": "null-password", "password": None},
            {"username": "number-password", "password": 123},
            {"username": "object-password", "password": {}},
            [],
            ["username", "password"],
            "not-an-object",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.client.post("/register", json=payload)
                self.assertEqual(response.status_code, 400)
        for data in ({}, {"username": "form-user", "password": ""}):
            with self.subTest(form=data):
                self.assertEqual(self.client.post("/register", data=data).status_code, 400)

    def test_malformed_or_non_json_registration_returns_400(self):
        for data, content_type in (
            ('{"username":', "application/json"),
            ("null", "application/json"),
            ("plain text", "text/plain"),
        ):
            with self.subTest(data=data):
                response = self.client.post("/register", data=data, content_type=content_type)
                self.assertEqual(response.status_code, 400)

    def test_note_owner_can_read_own_note(self):
        self.login()
        response = self.client.get("/api/notes/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"id": 1, "owner": "alice", "title": "groceries", "body": "milk, eggs"},
        )

    def test_other_owner_and_missing_note_are_indistinguishable(self):
        self.login()
        other = self.client.get("/api/notes/2")
        missing = self.client.get("/api/notes/999999")
        self.assertEqual(other.status_code, 404)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(other.get_json(), missing.get_json())
        self.assertNotIn("hunter2", other.get_data(as_text=True))
        self.assertNotIn("admin", other.get_data(as_text=True))

    def test_admin_note_access_still_requires_ownership(self):
        self.login("admin", "admin123")
        self.assertEqual(self.client.get("/api/notes/2").status_code, 200)
        self.assertEqual(self.client.get("/api/notes/1").status_code, 404)

    def test_note_api_requires_authentication(self):
        for note_id in (1, 2, 999999):
            with self.subTest(note_id=note_id):
                response = self.client.get("/api/notes/%d" % note_id)
                self.assertEqual(response.status_code, 401)
                self.assertNotIn("owner", response.get_json())

    def test_admin_response_excludes_password_hashes(self):
        self.login("admin", "admin123")
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        users = response.get_json()
        self.assertEqual({user["username"] for user in users}, {"alice", "admin"})
        for user in users:
            self.assertEqual(set(user), {"id", "username", "role"})
        con = notevault.db()
        try:
            stored_hashes = [r["password"] for r in con.execute("SELECT password FROM users")]
        finally:
            con.close()
        for stored_hash in stored_hashes:
            self.assertNotIn(stored_hash, response.get_data(as_text=True))

    def test_admin_still_rejects_anonymous_and_regular_users(self):
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.login()
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_stored_html_is_escaped_on_home_and_search(self):
        self.login()
        title = '<script>alert("title")</script>{{7*7}}'
        body = '<img src=x onerror=alert("body")> & hello {{7*7}}'
        response = self.client.post("/notes", data={"title": title, "body": body})
        self.assertEqual(response.status_code, 302)
        for path in ("/", "/search?q="):
            with self.subTest(path=path):
                page = self.client.get(path)
                self.assertEqual(page.status_code, 200)
                text = page.get_data(as_text=True)
                self.assertNotIn("<script>", text)
                self.assertNotIn("<img src=x", text)
                self.assertIn("&lt;script&gt;", text)
                self.assertIn("&lt;img src=x", text)
                self.assertIn("&amp; hello", text)
                self.assertEqual(text.count("{{7*7}}"), 2)

    def test_normal_notes_render_without_leaking_another_users_notes(self):
        self.login()
        for path in ("/", "/search?q=milk"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                text = response.get_data(as_text=True)
                self.assertIn("groceries", text)
                self.assertIn("milk, eggs", text)
                self.assertNotIn("hunter2", text)
                self.assertNotIn("build-tag", text)

    def test_export_escapes_subprocess_output_without_running_a_command(self):
        self.login()
        with patch.object(notevault.subprocess, "run") as command:
            command.return_value.stdout = '<script>alert("export")</script> & exported'
            response = self.client.get("/export?fmt=txt")
        command.assert_called_once()
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("&amp; exported", text)

    def test_direct_startup_disables_debug_without_starting_a_server(self):
        real_connect = sqlite3.connect
        startup_db = str(Path(self.temp_dir.name) / "startup.db")

        def isolated_connect(database, *args, **kwargs):
            return real_connect(startup_db, *args, **kwargs)

        with patch("sqlite3.connect", side_effect=isolated_connect), patch.object(Flask, "run") as run, patch.dict(
            os.environ, {"FLASK_DEBUG": "1"}
        ):
            runpy.run_path(str(APP_PATH), run_name="__main__")
        run.assert_called_once()
        self.assertIs(run.call_args.kwargs.get("debug"), False)
        self.assertIs(run.call_args.kwargs.get("use_debugger"), False)
        self.assertIs(run.call_args.kwargs.get("use_reloader"), False)


if __name__ == "__main__":
    unittest.main()
