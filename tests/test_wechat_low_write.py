"""Low-write regressions using synthetic SQLite/WCDB fixtures only."""

import hashlib
import hmac
import json
import os
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from Crypto.Cipher import AES
from wechat_mcp import config, database, events, low_write, records, sources, auto_sync
from wechat_mcp.change_watch import ChangeWatch, relevant_event

# Public deterministic fixture material; never real account keys or payloads.
KEY = bytes(range(32))
SALT = bytes(range(16))
ROOM = "fixture-room"
TABLE = "Msg_" + hashlib.md5(ROOM.encode()).hexdigest()


def empty_database():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE discard(a)")
    conn.execute("DROP TABLE discard")
    conn.execute("VACUUM")
    image = bytearray(conn.serialize())
    conn.close()
    image[20] = 80  # WCDB reserve: IV + SHA512 HMAC.
    image[105:107] = struct.pack(">H", 4096 - 80)
    conn = sqlite3.connect(":memory:")
    conn.deserialize(bytes(image))
    return conn


def image_for(kind, messages=((1, "first", 10),)):
    conn = empty_database()
    if kind == "message":
        conn.execute("CREATE TABLE Name2Id(user_name TEXT)")
        conn.execute("INSERT INTO Name2Id VALUES (?)", (ROOM,))
        conn.execute(
            f"CREATE TABLE {TABLE}(local_id INTEGER, real_sender_id INTEGER, local_type INTEGER, create_time INTEGER, message_content TEXT, source TEXT)"
        )
        conn.executemany(
            f"INSERT INTO {TABLE} VALUES (?,1,1,?,?,NULL)",
            ((i, ts, text) for i, text, ts in messages),
        )
    elif kind == "session":
        conn.execute(
            "CREATE TABLE SessionTable(username TEXT, summary TEXT, last_timestamp INTEGER, unread_count INTEGER)"
        )
        conn.execute("INSERT INTO SessionTable VALUES (?, 'first', 10, 1)", (ROOM,))
    elif kind == "contact":
        conn.execute(
            "CREATE TABLE contact(username TEXT, alias TEXT, remark TEXT, nick_name TEXT, local_type INTEGER)"
        )
        conn.execute("INSERT INTO contact VALUES (?, '', '', 'Fixture', 0)", (ROOM,))
    conn.commit()
    image = conn.serialize()
    conn.close()
    return image


def encrypt_page(page, number):
    start = 16 if number == 1 else 0
    iv = number.to_bytes(16, "little")
    cipher = AES.new(KEY, AES.MODE_CBC, iv).encrypt(page[start:4016])
    prefix = (SALT if number == 1 else b"") + cipher + iv
    mac = hashlib.pbkdf2_hmac("sha512", KEY, bytes(b ^ 0x3A for b in SALT), 2, dklen=32)
    digest = hmac.new(
        mac, prefix[start:] + struct.pack("<I", number), hashlib.sha512
    ).digest()
    return prefix + digest


def encrypt_image(image):
    return b"".join(
        encrypt_page(image[i : i + 4096], i // 4096 + 1)
        for i in range(0, len(image), 4096)
    )


def make_wal(frames, salt=b"abcdefgh"):
    header = struct.pack(
        ">6I", 0x377F0682, 3007000, 4096, 0, *struct.unpack(">II", salt)
    )
    state = low_write._checksum(header)
    output = header + struct.pack(">II", *state)
    for number, size, page in frames:
        first = struct.pack(">II", number, size)
        encrypted = encrypt_page(page, number)
        state = low_write._checksum(first + encrypted, state)
        output += first + salt + struct.pack(">II", *state) + encrypted
    return output


class TestMemoryDecode(unittest.TestCase):
    def test_authenticated_round_trip_and_read_only(self):
        image = image_for("message")
        decoded = low_write.decrypt_image(encrypt_image(image), b"", KEY)
        conn = sources.memory_connection(decoded)
        self.addCleanup(conn.close)
        self.assertEqual(
            conn.execute(f"SELECT message_content FROM {TABLE}").fetchone()[0], "first"
        )
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute(f"DELETE FROM {TABLE}")

    def test_bad_key_and_corrupt_later_page_rejected(self):
        encrypted = bytearray(encrypt_image(image_for("message")))
        with self.assertRaises(ValueError):
            low_write.decrypt_image(bytes(encrypted), b"", bytes(32))
        encrypted[4200] ^= 1
        with self.assertRaises(ValueError):
            low_write.decrypt_image(bytes(encrypted), b"", KEY)

    def test_committed_wal_and_uncommitted_tail(self):
        base = image_for("message")
        updated = image_for("message", ((1, "changed", 10),))
        # The changed message lives in page 3, discovered from byte differences.
        changed = [
            i // 4096 + 1
            for i in range(0, len(base), 4096)
            if base[i : i + 4096] != updated[i : i + 4096]
        ]
        frames = [
            (
                n,
                len(updated) // 4096 if j == len(changed) - 1 else 0,
                updated[(n - 1) * 4096 : n * 4096],
            )
            for j, n in enumerate(changed)
        ]
        # Valid but uncommitted page is ignored.
        frames.append((1, 0, base[:4096]))
        result = low_write.decrypt_image(encrypt_image(base), make_wal(frames), KEY)
        conn = sources.memory_connection(result)
        self.addCleanup(conn.close)
        self.assertEqual(
            conn.execute(f"SELECT message_content FROM {TABLE}").fetchone()[0],
            "changed",
        )

    def test_reused_wal_tail_and_invalid_checksum_are_ignored(self):
        image = image_for("message")
        valid = make_wal([(1, len(image) // 4096, image[:4096])])
        stale = make_wal([(1, len(image) // 4096, image[:4096])], salt=b"old-tail")[32:]
        self.assertEqual(
            low_write.decrypt_image(encrypt_image(image), valid + stale, KEY), image
        )
        damaged = bytearray(valid)
        damaged[60] ^= 1
        self.assertEqual(
            low_write.decrypt_image(encrypt_image(image), bytes(damaged), KEY), image
        )

    def test_invalid_wal_header_fails_closed(self):
        image = image_for("message")
        with self.assertRaises(ValueError):
            low_write.decrypt_image(encrypt_image(image), b"incomplete", KEY)

    def test_wcdb_custom_tokenizer_keeps_ordinary_table_checks(self):
        # Build a schema with equal-length substitution so SQLite record sizes
        # remain valid; the registered tokenizer is only needed while creating.
        conn = empty_database()
        conn.execute(
            "CREATE VIRTUAL TABLE fixture_fts USING fts5(content, tokenize='unicode61     ')"
        )
        conn.execute("CREATE TABLE ordinary(value TEXT)")
        conn.execute("INSERT INTO ordinary VALUES ('fixture')")
        conn.commit()
        image = conn.serialize().replace(b"unicode61     ", b"MMFtsTokenizer")
        ordinary_root = conn.execute(
            "SELECT rootpage FROM sqlite_master WHERE name='ordinary'"
        ).fetchone()[0]
        conn.close()
        low_write.validate_image(image)
        damaged = bytearray(image)
        damaged[(ordinary_root - 1) * 4096] = 0
        with self.assertRaises((ValueError, sqlite3.Error)):
            low_write.validate_image(bytes(damaged))


class TestResidentSync(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.root = self.home / "decrypted"
        self.origin = self.home / "encrypted"
        self.origin.mkdir()
        self.index = self.home / "app.db"
        for mod in (config, database):
            p = patch.object(mod, "DB_PATH", self.index)
            p.start()
            self.addCleanup(p.stop)
        for obj, attr, value in (
            (config, "USER_WECHAT_DIR", self.home),
            (config, "DEFAULT_DECRYPTED_DIR", self.root),
            (records, "get_decrypted_dir", lambda: self.root),
        ):
            p = patch.object(obj, attr, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(
            os.environ,
            {
                "WECHAT_SYNC_MODE": "memory",
                "WECHAT_DB_DIR": str(self.origin),
                "WECHAT_DECRYPTED_DIR": str(self.root),
            },
        )
        p.start()
        self.addCleanup(p.stop)
        low_write._cache.clear()
        sources._published = None
        self.addCleanup(low_write._cache.clear)
        self.addCleanup(setattr, sources, "_published", None)
        self.addCleanup(database.release_connections)
        self.put("message/message_0.db", image_for("message"))
        self.put("session/session.db", image_for("session"))
        self.put("contact/contact.db", image_for("contact"))
        self.keys = {
            p.relative_to(self.origin).as_posix(): {"enc_key": KEY.hex()}
            for p in self.origin.rglob("*.db")
        }
        (self.home / "all_keys.json").write_text(
            json.dumps(self.keys), encoding="utf-8"
        )

    def put(self, name, image):
        path = self.origin / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encrypt_image(image))

    def sync(self, **kw):
        result = low_write.sync_memory(**kw)
        self.assertTrue(result["ok"], result)
        return result

    def query(self, sql):
        conn = sqlite3.connect(self.index)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    def test_idle_has_no_index_or_plaintext_writes(self):
        self.sync()
        stamp = self.index.stat().st_mtime_ns
        before = self.index.read_bytes()
        with (
            patch.object(
                low_write,
                "decrypt_image",
                side_effect=AssertionError("idle decryption"),
            ),
            patch.object(
                database, "sync_memory_source", side_effect=AssertionError("idle ETL")
            ),
        ):
            self.assertEqual(self.sync()["etl_step"]["status"], "skipped")
        self.assertEqual(before, self.index.read_bytes())
        self.assertEqual(stamp, self.index.stat().st_mtime_ns)
        self.assertFalse(self.root.exists())
        self.assertEqual(events.pending_events(), [])

    def test_append_edit_historical_insert_delete_and_fts(self):
        self.sync()
        original_id = self.query("SELECT id FROM messages")[0][0]
        self.put(
            "message/message_0.db",
            image_for(
                "message", ((1, "revised", 10), (3, "later", 30), (2, "history", 5))
            ),
        )
        with patch.object(
            low_write, "decrypt_image", wraps=low_write.decrypt_image
        ) as decoder:
            self.assertEqual(self.sync()["decrypt_step"]["changed_databases"], 1)
            self.assertEqual(decoder.call_count, 1)
        self.assertEqual(
            self.query("SELECT id FROM messages WHERE local_id=1")[0][0], original_id
        )
        self.assertEqual(
            self.query(
                "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'first'"
            )[0][0],
            0,
        )
        self.assertEqual(
            self.query(
                "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'revised'"
            )[0][0],
            1,
        )
        self.assertEqual(
            self.query("SELECT message_count,first_time FROM sessions"), [(3, 5)]
        )
        self.assertEqual(
            [e["kind"] for e in events.pending_events()].count("message.created"), 2
        )
        self.put("message/message_0.db", image_for("message", ((1, "revised", 10),)))
        self.sync()
        self.assertEqual(self.query("SELECT COUNT(*) FROM messages"), [(1,)])
        self.assertEqual(
            [e["kind"] for e in events.pending_events()].count("message.deleted"), 2
        )

    def test_force_identical_rows_does_not_churn_ids_or_events(self):
        self.sync()
        before = self.query("SELECT * FROM messages")
        sequence = self.query("SELECT seq FROM sqlite_sequence WHERE name='messages'")
        self.assertEqual(self.sync(force=True)["etl_step"]["changed_rows"], 0)
        self.assertEqual(before, self.query("SELECT * FROM messages"))
        self.assertEqual(
            sequence,
            self.query("SELECT seq FROM sqlite_sequence WHERE name='messages'"),
        )
        self.assertEqual(events.pending_events(), [])

    def test_raw_payload_reads_published_memory(self):
        self.sync()
        self.assertEqual(records.find_raw_content("message_0.db", 1, 10), "first")
        conn = sources.connect_source(self.root / "message/message_0.db")
        self.addCleanup(conn.close)
        self.put("message/message_0.db", image_for("message", ((1, "updated", 10),)))
        self.sync()
        self.assertEqual(
            conn.execute(f"SELECT message_content FROM {TABLE}").fetchone()[0], "first"
        )
        self.assertEqual(records.find_raw_content("message_0.db", 1, 10), "updated")

    def test_corruption_and_etl_failure_retain_last_generation(self):
        self.sync()
        before = self.query("SELECT * FROM messages")
        self.put("message/message_0.db", image_for("message", ((1, "updated", 10),)))
        with patch.object(
            database, "sync_avatars_v4", side_effect=RuntimeError("fixture failure")
        ):
            self.assertFalse(low_write.sync_memory()["ok"])
        self.assertEqual(before, self.query("SELECT * FROM messages"))
        self.assertEqual(events.pending_events(), [])
        self.assertEqual(records.find_raw_content("message_0.db", 1, 10), "first")
        # Failed generation must be retried even with identical source metadata.
        self.sync()
        self.assertEqual(records.find_raw_content("message_0.db", 1, 10), "updated")
        (self.origin / "message/message_0.db").write_bytes(b"broken")
        self.assertFalse(low_write.sync_memory()["ok"])
        self.assertEqual(records.find_raw_content("message_0.db", 1, 10), "updated")

    def test_restart_and_event_acknowledgement(self):
        self.sync()
        low_write._cache.clear()
        self.put(
            "message/message_0.db",
            image_for("message", ((1, "first", 10), (2, "new", 20))),
        )
        self.sync()
        pending = events.pending_events()
        self.assertEqual(len(pending), 1)
        self.assertEqual(events.wait_for_events(timeout=0), pending)
        events.acknowledge_events([pending[0]["id"]])
        events.acknowledge_events([pending[0]["id"]])
        self.assertEqual(events.pending_events(), [])

    def test_new_and_removed_shards(self):
        self.sync()
        self.put(
            "message/message_1.db", image_for("message", ((2, "second shard", 20),))
        )
        self.keys["message/message_1.db"] = {"enc_key": KEY.hex()}
        (self.home / "all_keys.json").write_text(
            json.dumps(self.keys), encoding="utf-8"
        )
        self.sync()
        self.assertEqual(self.query("SELECT COUNT(*) FROM messages"), [(2,)])
        (self.origin / "message/message_1.db").unlink()
        self.sync()
        self.assertEqual(self.query("SELECT COUNT(*) FROM messages"), [(1,)])

    def test_wal_only_change_detected(self):
        self.sync()
        base = image_for("message")
        updated = image_for("message", ((1, "via WAL", 10),))
        pages = [
            n // 4096 + 1
            for n in range(0, len(base), 4096)
            if base[n : n + 4096] != updated[n : n + 4096]
        ]
        frames = [
            (
                n,
                len(updated) // 4096 if i == len(pages) - 1 else 0,
                updated[(n - 1) * 4096 : n * 4096],
            )
            for i, n in enumerate(pages)
        ]
        (self.origin / "message/message_0.db-wal").write_bytes(make_wal(frames))
        self.sync()
        self.assertEqual(self.query("SELECT content FROM messages"), [("via WAL",)])

    def test_source_changes_during_capture_never_accepted(self):
        cache = low_write.SnapshotCache()
        state = low_write.scan(self.origin)
        altered = dict(state)
        altered["message/message_0.db"] = (None, None)
        with patch.object(low_write, "scan", side_effect=[state, altered] * 3):
            with self.assertRaises(RuntimeError):
                cache.prepare(
                    self.origin, (self.home / "all_keys.json").read_bytes(), self.root
                )
        self.assertEqual(cache.images, {})

    def test_event_is_not_visible_before_transaction_commit(self):
        self.sync()
        with closing(sqlite3.connect(self.index)) as conn:
            with conn:
                conn.execute(
                    "INSERT INTO message_events(kind,message_id,created_at) VALUES ('message.created',1,0)"
                )
                self.assertEqual(events.pending_events(), [])
        self.assertEqual(len(events.pending_events()), 1)

    def test_no_concurrent_sync_and_no_detached_worker(self):
        with low_write.SYNC_LOCK:
            self.assertEqual(low_write.sync_memory()["etl_step"]["status"], "busy")
        with (
            patch.object(
                auto_sync,
                "_spawn_detached_worker",
                side_effect=AssertionError("must stay resident"),
            ),
            patch.object(auto_sync, "_sync_worker") as worker,
        ):
            result = auto_sync.start_sync()
            auto_sync._sync_thread.join(timeout=2)
            self.assertEqual(result["mode"], "resident")
            worker.assert_called_once()

    def test_idle_record_does_not_persist_state(self):
        with patch.object(
            auto_sync, "_save_state", side_effect=AssertionError("idle state write")
        ):
            auto_sync.record_run(
                {"ok": True, "etl_step": {"status": "skipped"}}, time.time()
            )


class TestChangeNotification(unittest.TestCase):
    def test_event_filter_ignores_reads_and_index(self):
        self.assertTrue(
            relevant_event(
                SimpleNamespace(
                    event_type="modified", is_directory=False, src_path="fixture.db-wal"
                )
            )
        )
        self.assertTrue(
            relevant_event(
                SimpleNamespace(
                    event_type="moved",
                    is_directory=False,
                    src_path="temp",
                    dest_path="fixture.db",
                )
            )
        )
        self.assertFalse(
            relevant_event(
                SimpleNamespace(
                    event_type="opened", is_directory=False, src_path="fixture.db"
                )
            )
        )

    def test_stop_and_notification_wait(self):
        watch = ChangeWatch(Path("."), Path("all_keys.json"))
        watch.event.set()
        self.assertTrue(watch.wait(threading.Event(), verification_seconds=1))
        stop = threading.Event()
        stop.set()
        self.assertFalse(watch.wait(stop))

    def test_native_watch_wakes_on_write(self):
        try:
            import watchdog
        except ImportError:
            self.skipTest("optional watchdog dependency unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            watch = ChangeWatch(root, root / "all_keys.json")
            watch.start()
            try:
                (root / "fixture.db-wal").write_bytes(b"event")
                self.assertTrue(watch.event.wait(3))
            finally:
                watch.close()
