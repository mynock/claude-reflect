#!/usr/bin/env python3
"""Tests for secret redaction before anything is stored.

Sample tokens are fake. A few are assembled at runtime so the literal never
appears in the repo, which keeps secret scanners and push protection quiet.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from lib.reflect_utils import (  # noqa: E402
    REDACTED,
    create_queue_item,
    extract_tool_errors,
    extract_tool_rejections,
    extract_user_messages,
    load_queue_at,
    redact_queue_items,
    redact_secrets,
    save_queue_at,
)

PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
GITHUB_TOKEN = "gh" + "p_" + "notarealtoken12345"
LONG_TOKEN = "a1B2" * 10  # 40 chars, letters and digits


class TestRedactSecrets(unittest.TestCase):
    """redact_secrets() on its own."""

    def assertRedacted(self, text, secret):
        out = redact_secrets(text)
        self.assertNotIn(secret, out)
        self.assertIn(REDACTED, out)
        return out

    def test_same_positives_as_reflect_mod(self):
        # The strings mod/hooks/reflect.test.tsx expects looksSecret() to flag.
        cases = [
            ("key sk-ant-abcdefghijklmnop", "sk-ant-abcdefghijklmnop"),
            ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
            ("пароль: hunter2", "hunter2"),
            ("password is hunter2", "hunter2"),
            ("eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0", "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0"),
        ]
        for text, secret in cases:
            with self.subTest(text=text):
                self.assertRedacted(text, secret)

    def test_same_negatives_as_reflect_mod(self):
        for text in [
            "Use pnpm, not npm",
            "the password flow is broken",
            "see /Users/bayramannakov/GH/claude-mods/reflect/hooks",
        ]:
            with self.subTest(text=text):
                self.assertEqual(redact_secrets(text), text)

    def test_keeps_the_correction_around_the_secret(self):
        out = redact_secrets("no, the staging password: hunter2 lives in vault, use that")
        self.assertEqual(out, "no, the staging password: [REDACTED], use that")

    def test_api_key_assignment(self):
        out = self.assertRedacted("remember: API_KEY=" + GITHUB_TOKEN, GITHUB_TOKEN)
        self.assertTrue(out.startswith("remember: API_KEY="))

    def test_provider_tokens(self):
        for secret in [
            GITHUB_TOKEN,
            "github_pat_" + "notreal_0123456789",
            "glpat-" + "notreal0123456789",
            "xoxb-" + "not-a-real-token",
            "AIza" + "SyNotARealGoogleKey0123",
        ]:
            with self.subTest(secret=secret):
                self.assertRedacted("use " + secret + " for CI", secret)

    def test_full_jwt_with_signature(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3NpZw"
        out = self.assertRedacted("token " + jwt + " expired", jwt)
        self.assertNotIn("c2lnbmF0dXJl", out)

    def test_url_password_keeps_user_and_host(self):
        out = redact_secrets("use postgres://app:s3cretpw@db.internal:5432/app not sqlite")
        self.assertEqual(out, "use postgres://app:[REDACTED]@db.internal:5432/app not sqlite")

    def test_url_without_password_untouched(self):
        for text in ["see https://example.com/a/b", "clone git@github.com:org/repo.git"]:
            with self.subTest(text=text):
                self.assertEqual(redact_secrets(text), text)

    def test_private_key_block_removed_whole(self):
        text = "remember: deploy key is\n" + PEM_BEGIN + "\nMIIBfakefakefake\nmorefake\n" + PEM_END + "\nthanks"
        out = redact_secrets(text)
        self.assertNotIn("MIIBfake", out)
        self.assertNotIn("PRIVATE KEY", out)
        self.assertTrue(out.startswith("remember: deploy key is\n"))
        self.assertTrue(out.endswith("\nthanks"))

    def test_private_key_without_end_line(self):
        out = redact_secrets("key: " + PEM_BEGIN + "\nMIIBfakefake")
        self.assertNotIn("MIIBfake", out)

    def test_aws_secret_access_key_and_temporary_key_id(self):
        aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        out = self.assertRedacted("AWS_SECRET_ACCESS_KEY=" + aws_secret, aws_secret)
        self.assertEqual(out, "AWS_SECRET_ACCESS_KEY=[REDACTED]")
        self.assertRedacted("use ASIAIOSFODNN7EXAMPLE for the session", "ASIAIOSFODNN7EXAMPLE")

    def test_quoted_json_and_config_values(self):
        self.assertEqual(
            redact_secrets('{"password": "hunter2", "user": "bob"}'),
            '{"password": "[REDACTED]", "user": "bob"}',
        )
        self.assertEqual(
            redact_secrets("DB_PASSWORD='correct horse battery'"),
            "DB_PASSWORD='[REDACTED]'",
        )

    def test_passphrase_with_spaces(self):
        self.assertEqual(
            redact_secrets("password: my long passphrase"),
            "password: [REDACTED]",
        )

    def test_url_password_with_empty_user(self):
        self.assertEqual(
            redact_secrets("use redis://:hunter2pw@cache:6379 not localhost"),
            "use redis://:[REDACTED]@cache:6379 not localhost",
        )

    def test_bearer_and_basic_auth(self):
        for text, secret in [
            ("Authorization: Bearer abc123def456ghi", "abc123def456ghi"),
            ("curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZA=='", "dXNlcjpwYXNzd29yZA=="),
        ]:
            with self.subTest(text=text):
                out = self.assertRedacted(text, secret)
                self.assertIn("Authorization:", out)

    def test_pgp_private_key_block(self):
        begin = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"
        end = "-----END PGP " + "PRIVATE KEY BLOCK-----"
        out = redact_secrets("key\n" + begin + "\nlQOYBfake\n" + end + "\nok")
        self.assertNotIn("lQOYBfake", out)
        self.assertTrue(out.endswith("\nok"))

    def test_long_names_are_not_tokens(self):
        for text in [
            "dont edit 0042_auto_20240101_add_column_to_users",
            "call handleOAuth2CallbackForGoogleProviderNow instead",
            "set max_tokens: 4096",
            "the tokenizer: tiktoken",
            "test_capture_hook_stores_and_prints_redacted_v2 is flaky",
        ]:
            with self.subTest(text=text):
                self.assertEqual(redact_secrets(text), text)

    def test_digest_with_prefix_kept_bare_hex_redacted(self):
        digest = "ab12" * 16  # 64 hex characters
        kept = "pin the image to sha256:" + digest
        self.assertEqual(redact_secrets(kept), kept)
        self.assertRedacted("the key is " + digest, digest)

    def test_long_opaque_token(self):
        for token in [LONG_TOKEN, "Zq9" * 12]:
            with self.subTest(token=token):
                self.assertRedacted("set the header to " + token, token)

    def test_mixed_case_hex_is_not_mistaken_for_a_git_sha(self):
        # LONG_TOKEN is 40 hex characters, but git prints SHAs in lowercase.
        self.assertRedacted(LONG_TOKEN, LONG_TOKEN)

    def test_git_sha_and_uuid_are_kept(self):
        for text in [
            "pin to commit 3f2a9c1b7e4d5f6a8b9c0d1e2f3a4b5c6d7e8f90",
            "the tenant is 123e4567-e89b-12d3-a456-426614174000, not the default",
        ]:
            with self.subTest(text=text):
                self.assertEqual(redact_secrets(text), text)

    def test_idempotent(self):
        once = redact_secrets("password: hunter2 and " + GITHUB_TOKEN)
        self.assertEqual(redact_secrets(once), once)

    def test_non_strings_pass_through(self):
        self.assertIsNone(redact_secrets(None))
        self.assertEqual(redact_secrets(""), "")


class TestRedactionAtStorage(unittest.TestCase):
    """Every path that stores or prints captured text redacts it."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_session(self, entries):
        path = self.temp_dir / "session.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        return path

    def test_create_queue_item_redacts_message(self):
        item = create_queue_item(
            message="remember: the api key is " + GITHUB_TOKEN,
            item_type="explicit",
            patterns="remember:",
            confidence=0.9,
            sentiment="correction",
            decay_days=120,
            project="/p",
        )
        self.assertNotIn(GITHUB_TOKEN, item["message"])
        self.assertTrue(item["message"].startswith("remember: the api key is"))

    def test_redact_queue_items_does_not_mutate(self):
        items = [{"message": "password: hunter2", "type": "auto"}, "not-a-dict"]
        out = redact_queue_items(items)
        self.assertEqual(items[0]["message"], "password: hunter2")
        self.assertEqual(out[0]["message"], "password: [REDACTED]")
        self.assertEqual(out[0]["type"], "auto")
        self.assertEqual(out[1], "not-a-dict")

    def test_extract_user_messages_redacts(self):
        session = self._write_session([
            {"type": "user", "message": {"content": "no, use postgres://app:s3cretpw@db/app"}},
            {"type": "user", "message": {"content": [
                {"type": "text", "text": "remember: token = " + GITHUB_TOKEN},
            ]}},
        ])
        messages = extract_user_messages(session)
        self.assertEqual(len(messages), 2)
        joined = "\n".join(messages)
        self.assertNotIn("s3cretpw", joined)
        self.assertNotIn(GITHUB_TOKEN, joined)

    def test_extract_tool_rejections_redacts(self):
        session = self._write_session([
            {"type": "user", "message": {"content": [{
                "type": "tool_result",
                "is_error": True,
                "content": "The user doesn't want to proceed\nthe user said:\nuse " + GITHUB_TOKEN + " instead",
            }]}},
        ])
        rejections = extract_tool_rejections(session)
        self.assertEqual(rejections, ["use [REDACTED] instead"])

    def test_extract_tool_errors_redacts_samples(self):
        session = self._write_session([
            {"type": "user", "message": {"content": [{
                "type": "tool_result",
                "is_error": True,
                "content": "psql postgres://app:s3cretpw@db:5432/app: Connection refused",
            }]}},
        ])
        errors = extract_tool_errors(session)
        self.assertEqual(len(errors), 1)
        self.assertNotIn("s3cretpw", errors[0]["content"])

    def test_capture_hook_stores_and_prints_redacted(self):
        project_folder = self.temp_dir / "projects" / "-tmp-proj"
        project_folder.mkdir(parents=True)
        payload = {
            "prompt": "remember: the staging api key is sk-ant-abcdefghijklmnop",
            "transcript_path": str(project_folder / "session.jsonl"),
        }
        env = dict(os.environ, HOME=str(self.temp_dir), USERPROFILE=str(self.temp_dir))
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "capture_learning.py")],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            cwd=str(self.temp_dir),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        queue_text = (project_folder / "learnings-queue.json").read_text(encoding="utf-8")
        self.assertIn("remember: the staging api key is", queue_text)
        self.assertNotIn("sk-ant-abcdefghijklmnop", queue_text)
        self.assertNotIn("sk-ant-abcdefghijklmnop", result.stdout)

    def test_load_queue_at_redacts_a_queue_saved_before_redaction(self):
        queue = self.temp_dir / "learnings-queue.json"
        queue.write_text(json.dumps([
            {"type": "explicit", "message": "remember: API_KEY=" + GITHUB_TOKEN},
        ]), encoding="utf-8")
        items = load_queue_at(queue)
        self.assertEqual(items[0]["message"], "remember: API_KEY=[REDACTED]")

    def test_load_queue_at_rejects_non_list(self):
        queue = self.temp_dir / "learnings-queue.json"
        queue.write_text(json.dumps({"message": "not a queue"}), encoding="utf-8")
        self.assertEqual(load_queue_at(queue), [])

    def test_save_queue_at_redacts(self):
        queue = self.temp_dir / "learnings-queue.json"
        save_queue_at(queue, [{"type": "auto", "message": "password: hunter2"}])
        self.assertNotIn("hunter2", queue.read_text(encoding="utf-8"))

    def test_corrections_only_filter_still_applies(self):
        session = self._write_session([
            {"type": "user", "message": {"content": "no, use token = " + GITHUB_TOKEN}},
            {"type": "user", "message": {"content": "looks good, ship it"}},
        ])
        self.assertEqual(
            extract_user_messages(session, corrections_only=True),
            ["no, use token = [REDACTED]"],
        )

    def test_redact_cli(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "redact.py")],
            input="use postgres://app:s3cretpw@db/app\n",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "use postgres://app:[REDACTED]@db/app\n")

    def test_precompact_backup_redacts_old_queue(self):
        import check_learnings

        # A queue written before redaction existed still holds the raw text.
        queue = self.temp_dir / "learnings-queue.json"
        queue.write_text(json.dumps([
            {"type": "explicit", "message": "remember: password is hunter2"},
        ]), encoding="utf-8")
        backup_dir = self.temp_dir / "learnings-backups"
        with patch.object(check_learnings, "load_queue", lambda: load_queue_at(queue)), \
             patch.object(check_learnings, "get_backup_dir", return_value=backup_dir), \
             patch.object(check_learnings, "ensure_utf8_io"), \
             patch("sys.stdout"):
            self.assertEqual(check_learnings.main(), 0)

        backups = list(backup_dir.glob("pre-compact-*.json"))
        self.assertEqual(len(backups), 1)
        saved = json.loads(backups[0].read_text(encoding="utf-8"))
        self.assertEqual(saved[0]["message"], "remember: password is [REDACTED]")


if __name__ == "__main__":
    unittest.main()
