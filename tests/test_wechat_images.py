"""Synthetic image fixtures only; no account data, real keys or remote services."""

import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

from wechat_mcp import config, database, images, server

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a3ioAAAAASUVORK5CYII="
)
DIGEST = "a" * 32
SESSION = "fixture-group@chatroom"


class ImageFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = self.root / "account"
        self.mirror = self.root / "decrypted"
        self.source = self.mirror / "db_storage"
        self.user = self.root / "state"
        self.user.mkdir()
        self.index = self.root / "index.db"
        with closing(sqlite3.connect(self.index)) as conn, conn:
            conn.execute(
                "CREATE TABLE messages (id,local_type,content,source_file,local_id,create_time,session_username)"
            )
            conn.execute(
                "INSERT INTO messages VALUES (1,3,?, ?,7,1234,?)",
                ("[图片]", "message_0.db", SESSION),
            )
        (self.source / "message").mkdir(parents=True)
        self.source_db = self.source / "message/message_0.db"
        with closing(sqlite3.connect(self.source_db)) as conn, conn:
            # An unrelated chat has the same local ID and timestamp.
            for session, digest in [("unrelated", "b" * 32), (SESSION, DIGEST)]:
                table = "Msg_" + hashlib.md5(session.encode()).hexdigest()
                conn.execute(
                    f'CREATE TABLE "{table}" (local_id,create_time,packed_info_data)'
                )
                conn.execute(
                    f'INSERT INTO "{table}" VALUES (7,1234,?)', (digest.encode(),)
                )
        self.image = self.original / f"msg/attach/fixture-chat/2025-06/Img/{DIGEST}.dat"
        self.image.parent.mkdir(parents=True)
        self.image.write_bytes(bytes(b ^ 0x5A for b in PNG))
        for name, value in [
            ("get_files_root", lambda: self.original),
            ("get_decrypted_dir", lambda: self.source),
            ("get_decrypted_files_root", lambda: self.mirror),
            ("USER_WECHAT_DIR", self.user),
        ]:
            self.enterContext(patch.object(images, name, value))
        self.enterContext(
            patch.object(
                database, "get_connection", lambda: sqlite3.connect(self.index)
            )
        )

    def test_configured_account_and_exact_chat_row(self):
        result = images.get_image_for_message(1, include_base64=True)
        self.assertTrue(result["success"])
        expected = self.mirror / self.image.relative_to(self.original).with_suffix(
            ".png"
        )
        self.assertEqual(Path(result["file_path"]), expected)
        self.assertEqual(expected.read_bytes(), PNG)
        self.assertEqual(base64.b64decode(result["base64"]), PNG)
        self.assertEqual(result["mime_type"], "image/png")
        self.assertFalse(result["is_thumbnail"])

    def test_repeat_read_does_not_rewrite_and_changed_content_replaces(self):
        first = images.get_image_for_message(1)
        output = Path(first["file_path"])
        stamp = output.stat().st_mtime_ns
        with patch.object(images.os, "replace", wraps=images.os.replace) as replace:
            self.assertTrue(images.get_image_for_message(1)["success"])
            replace.assert_not_called()
        self.assertEqual(output.stat().st_mtime_ns, stamp)
        changed = PNG + b"synthetic-change"
        self.image.write_bytes(bytes(b ^ 0x5A for b in changed))
        self.assertTrue(images.get_image_for_message(1)["success"])
        self.assertEqual(output.read_bytes(), changed)

    def test_missing_file_and_missing_key_are_distinct(self):
        self.image.unlink()
        self.assertEqual(
            images.get_image_for_message(1)["error_code"], "image_not_downloaded"
        )
        self.image.write_bytes(images._V2_MAGIC_FULL + b"\0" * 40)
        with patch.object(images, "_try_extract_image_key", return_value=False):
            self.assertEqual(
                images.get_image_for_message(1)["error_code"], "image_key_missing"
            )

    def test_original_is_preferred_over_thumbnail(self):
        thumbnail = self.image.with_name(DIGEST + "_t.dat")
        thumbnail.write_bytes(self.image.read_bytes())
        self.assertEqual(
            images._find_image_dat_by_md5(DIGEST, [self.original]), self.image
        )
        self.image.unlink()
        result = images.get_image_for_message(1)
        self.assertTrue(result["is_thumbnail"])
        self.assertIn("small text", result["warning"])
        self.assertEqual(Path(result["file_path"]).stem, DIGEST + "_t")

    def test_private_container_preserved_and_readable_thumbnail_returned(self):
        thumbnail = self.image.with_name(DIGEST + "_t.dat")
        thumbnail.write_bytes(b"fixture")

        def decrypt(path, aes_key=None):
            return (
                (PNG, "png", None)
                if path == thumbnail
                else (b"wxgf" + b"fixture", "wxgf", None)
            )

        # Real wxgf thumbnail is JPEG; use a mock JPEG header here, no decoding needed.
        with patch.object(
            images,
            "decrypt_image_dat",
            side_effect=lambda path, aes_key=None: (
                (b"\xff\xd8\xff" + b"fixture", "jpg", None)
                if path == thumbnail
                else decrypt(path)
            ),
        ):
            result = images.get_image_for_message(1)
        self.assertTrue(result["is_thumbnail"])
        self.assertEqual(Path(result["file_path"]).name, DIGEST + "_t.jpg")
        original = self.mirror / self.image.relative_to(self.original).with_suffix(
            ".wxgf"
        )
        self.assertTrue(original.read_bytes().startswith(b"wxgf"))

    def test_mirror_rejects_paths_outside_account(self):
        with self.assertRaises(ValueError):
            images._save_mirrored_image(
                self.root / "outside.dat", [self.original], PNG, "png"
            )
        self.assertIsNone(images._find_image_dat_by_md5("../escape", [self.original]))


class ImageToolResult(unittest.IsolatedAsyncioTestCase):
    async def test_standard_image_content_without_base64_text_dump(self):
        fixture = {
            "success": True,
            "format": "png",
            "mime_type": "image/png",
            "base64": base64.b64encode(PNG).decode(),
            "is_thumbnail": False,
        }
        with (
            patch.object(server, "_check_db_initialized", return_value=None),
            patch.object(server, "get_image_for_message", return_value=fixture),
        ):
            result = await server.mcp.call_tool("get_message_image", {"message_id": 1})
        self.assertEqual([c.type for c in result.content], ["text", "image"])
        self.assertEqual(result.content[1].mimeType, "image/png")
        self.assertEqual(base64.b64decode(result.content[1].data), PNG)
        self.assertNotIn("base64", result.structuredContent)
        self.assertNotIn("base64", json.loads(result.content[0].text))
        self.assertFalse(result.isError)

    async def test_metadata_only_and_explicit_legacy_payload(self):
        fixture = {
            "success": True,
            "mime_type": "image/png",
            "base64": base64.b64encode(PNG).decode(),
        }
        with (
            patch.object(server, "_check_db_initialized", return_value=None),
            patch.object(server, "get_image_for_message", return_value=fixture),
        ):
            result = await server.mcp.call_tool(
                "get_message_image",
                {"message_id": 1, "return_image": False, "include_base64": True},
            )
        self.assertEqual([c.type for c in result.content], ["text"])
        self.assertIn("base64", result.structuredContent)
        self.assertNotIn("base64", result.content[0].text)

    async def test_errors_are_explicit_mcp_tool_errors(self):
        with (
            patch.object(server, "_check_db_initialized", return_value=None),
            patch.object(
                server,
                "get_image_for_message",
                return_value={
                    "error": "Missing key",
                    "error_code": "image_key_missing",
                },
            ),
        ):
            result = await server.mcp.call_tool("get_message_image", {"message_id": 1})
        self.assertTrue(result.isError)
        self.assertEqual(result.structuredContent["error_code"], "image_key_missing")
        self.assertEqual([c.type for c in result.content], ["text"])


class ImageCipherValidation(unittest.TestCase):
    def test_v2_decode_and_wrong_key_rejection(self):
        from Crypto.Cipher import AES

        key = b"0123456789abcdef"
        padding = 16 - len(PNG) % 16
        encoded = AES.new(key, AES.MODE_ECB).encrypt(PNG + bytes([padding]) * padding)
        payload = (
            images._V2_MAGIC_FULL + struct.pack("<II", len(PNG), 0) + b"\0" + encoded
        )
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.dat"
            path.write_bytes(payload)
            self.assertEqual(images.decrypt_image_dat(path, key), (PNG, "png", None))
            self.assertIsNotNone(images.decrypt_image_dat(path, b"fedcba9876543210")[2])
            path.write_bytes(payload[:-1])
            self.assertIsNotNone(images.decrypt_image_dat(path, key)[2])


class MirrorConfiguration(unittest.TestCase):
    def test_explicit_missing_account_does_not_fall_back_to_another_account(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing-account"
            with patch.dict("os.environ", {"WECHAT_FILES_ROOT": str(missing)}):
                self.assertEqual(config.get_files_root(), missing)

    def test_new_and_legacy_database_layouts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "decrypted"
            with (
                patch.dict("os.environ", {}, clear=True),
                patch.object(config, "DECRYPTED_FILES_DIR", root),
                patch.object(config, "DEFAULT_DECRYPTED_DIR", root / "db_storage"),
                patch.object(config, "BASE_DIR", Path(temp) / "project"),
            ):
                self.assertEqual(config.get_decrypted_dir(), root / "db_storage")
                self.assertEqual(config.get_decrypted_files_root(), root)
                (root / "message").mkdir(parents=True)
                (root / "message/fixture.db").touch()
                self.assertEqual(config.get_decrypted_dir(), root)
                (root / "db_storage").mkdir()
                self.assertEqual(config.get_decrypted_dir(), root / "db_storage")
                with patch.dict(
                    "os.environ",
                    {"WECHAT_DECRYPTED_DIR": str(Path(temp) / "custom/db_storage")},
                ):
                    self.assertEqual(
                        config.get_decrypted_files_root(), Path(temp) / "custom"
                    )


if __name__ == "__main__":
    unittest.main()
