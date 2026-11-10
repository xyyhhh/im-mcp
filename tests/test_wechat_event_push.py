"""Durability and protocol tests with synthetic message content only."""

import base64
from contextlib import closing
import hashlib
import hmac
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from wechat_mcp import events, event_push, event_relay

SECRET = "synthetic-secret-for-protocol-tests-only"


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / "index.db"
        with closing(sqlite3.connect(self.database)) as conn, conn:
            conn.executescript(
                "CREATE TABLE contacts(username PRIMARY KEY,display_name); CREATE TABLE sessions(username PRIMARY KEY,display_name);"
            )
            conn.execute("INSERT INTO contacts VALUES('fixture-owner','Fixture Owner')")
            conn.execute(
                "INSERT INTO sessions VALUES('fixture-group@chatroom','Fixture Group')"
            )
        self.transport = Mock()
        self.delivery = event_push.Delivery(
            self.database,
            {
                "source": "fixture-source",
                "owner_ids": ["fixture-owner"],
                "start_after_event_id": 0,
            },
            self.transport,
        )
        self.delivery.initialize()
        self.enterContext(
            patch.object(event_push, "message_mentions", return_value=["fixture-owner"])
        )

    def add_event(
        self, number=1, kind="message.created", text="Synthetic notice", snapshot=True
    ):
        data = {
            "source_file": "message_0.db",
            "local_id": 1,
            "session_username": "fixture-group@chatroom",
            "sender_username": "fixture-owner",
            "create_time": 1_700_000_000,
            "local_type": 1,
            "content": text,
        }
        with closing(self.delivery.connection()) as conn, conn:
            conn.execute(
                "INSERT INTO message_events(event_id,kind,message_id,created_at,snapshot) VALUES (?,?,1,0,?)",
                (
                    "fixture-event-" + str(number),
                    kind,
                    json.dumps(data) if snapshot else None,
                ),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM message_events WHERE event_id=?",
                    ("fixture-event-" + str(number),),
                ).fetchone()
            )

    def acknowledge(self, frame):
        event = json.loads(base64.b64decode(frame["body"]))
        return {"status": 202, "accepted": True, "event_id": event["event_id"]}

    def test_signed_payload_and_acknowledgement(self):
        event = self.add_event()
        self.transport.send.side_effect = self.acknowledge
        self.assertEqual(self.delivery.deliver(event, SECRET)[0], "sent")
        frame = self.transport.send.call_args.args[0]
        raw = base64.b64decode(frame["body"])
        expected = (
            "sha256="
            + hmac.new(
                SECRET.encode(),
                f'v1\n{frame["timestamp"]}\nPOST\n{event_relay.PATH}\n'.encode() + raw,
                hashlib.sha256,
            ).hexdigest()
        )
        self.assertEqual(frame["signature"], expected)
        body = json.loads(raw)
        self.assertTrue(body["is_self"])
        self.assertEqual(body["chat_type"], "group")
        self.assertEqual(body["mentions"], ["fixture-owner"])
        self.assertTrue(body["occurred_at"].endswith("+00:00"))
        self.assertEqual(self.delivery.pending(), [])
        with closing(self.delivery.connection()) as conn:
            self.assertIsNone(
                conn.execute("SELECT body FROM event_push_outbox").fetchone()[0]
            )

    def test_retry_body_is_immutable_even_after_local_data_changes(self):
        event = self.add_event()
        self.transport.send.return_value = {"status": 503, "accepted": False}
        self.assertEqual(self.delivery.deliver(event, SECRET)[0], "retry")
        first = self.transport.send.call_args.args[0]["body"]
        with closing(self.delivery.connection()) as conn, conn:
            conn.execute("UPDATE contacts SET display_name='Changed label'")
            conn.execute("UPDATE message_events SET snapshot=NULL")
        event["snapshot"] = None
        self.transport.send.side_effect = self.acknowledge
        self.assertEqual(self.delivery.deliver(event, SECRET)[0], "sent")
        self.assertEqual(first, self.transport.send.call_args.args[0]["body"])

    def test_no_acknowledgement_on_transport_loss_or_wrong_receipt(self):
        event = self.add_event()
        self.transport.send.side_effect = TimeoutError
        with self.assertRaises(TimeoutError):
            self.delivery.deliver(event, SECRET)
        self.assertEqual(len(self.delivery.pending()), 1)
        self.transport.send.side_effect = None
        self.transport.send.return_value = {
            "status": 200,
            "accepted": True,
            "event_id": "wrong-id",
        }
        self.assertEqual(self.delivery.deliver(event, SECRET)[0], "retry")
        self.assertEqual(len(self.delivery.pending()), 1)

    def test_bad_event_is_retained_without_blocking_later_messages(self):
        bad = self.add_event(snapshot=False)
        good = self.add_event(2)
        with self.assertLogs(event_push.logger, level="WARNING"):
            self.assertEqual(self.delivery.deliver(bad, SECRET)[0], "blocked")
        self.assertEqual([e["id"] for e in self.delivery.pending()], [good["id"]])
        with closing(self.delivery.connection()) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT acknowledged FROM message_events WHERE id=?", (bad["id"],)
                ).fetchone()[0],
                0,
            )

    def test_deletion_and_edit_preserve_context_and_distinct_event_ids(self):
        first = self.add_event()
        update = self.add_event(2, "message.updated", "Edited notice")
        deletion = self.add_event(3, "message.deleted", "Edited notice")
        edited = json.loads(self.delivery.freeze(update))
        deleted = json.loads(self.delivery.freeze(deletion))
        self.assertNotEqual(edited["event_id"], deleted["event_id"])
        self.assertEqual(deleted["reply_to"], first["event_id"])
        self.assertEqual(deleted["message_type"], "system")
        self.assertTrue(edited["text"].startswith("[消息更新]"))
        self.assertTrue(deleted["text"].startswith("[消息删除/撤回]"))

    def test_baseline_is_persistent_and_long_text_is_explicitly_truncated(self):
        event = self.add_event(text="x" * 9000)
        body = json.loads(self.delivery.freeze(event))
        self.assertEqual(len(body["text"]), 8000)
        self.assertIn("MCP", body["text"])
        other = event_push.Delivery(
            self.database, dict(self.delivery.settings, start_after_event_id=999)
        )
        other.initialize()
        self.assertEqual(other.baseline, 0)
        self.assertEqual(len(other.pending()), 1)

    def test_idle_worker_blocks_on_notification_without_database_polling(self):
        path = self.root / "secret"
        path.write_text(SECRET)
        self.delivery.settings["secret_file"] = str(path)

        def stop_wait():
            self.delivery.stop.set()

        with (
            patch.object(
                self.delivery, "pending", wraps=self.delivery.pending
            ) as pending,
            patch.object(events._ready, "wait", side_effect=stop_wait),
        ):
            self.delivery.run()
        self.assertEqual(pending.call_count, 1)
        self.transport.send.assert_not_called()


class RelayTests(unittest.TestCase):
    def test_event_schema_migrates_old_metadata_without_losing_acknowledgements(self):
        with sqlite3.connect(":memory:") as conn:
            conn.executescript(
                "CREATE TABLE message_events(id INTEGER PRIMARY KEY,event_id TEXT,kind TEXT,message_id INTEGER,created_at INTEGER,acknowledged INTEGER); INSERT INTO message_events VALUES(1,'fixture-old','message.created',1,0,1);"
            )
            events.ensure_schema(conn)
            events.ensure_schema(conn)
            self.assertEqual(
                conn.execute(
                    "SELECT event_id,acknowledged,snapshot FROM message_events"
                ).fetchone(),
                ("fixture-old", 1, None),
            )

    def test_relay_only_uses_fixed_loopback_endpoint(self):
        raw = json.dumps({"event_id": "fixture-event"}).encode()
        frame = event_push.signed_frame(raw, SECRET, timestamp=123)
        connection = Mock()
        response = connection.getresponse.return_value
        response.read.return_value = b'{"event_id":"fixture-event"}'
        response.status = 202
        response.getheader.return_value = None
        with patch.object(
            event_relay.http.client, "HTTPConnection", return_value=connection
        ) as constructor:
            result = event_relay.forward(frame)
        constructor.assert_called_once_with("127.0.0.1", 8768, timeout=15)
        self.assertEqual(
            connection.request.call_args.args[:3], ("POST", event_relay.PATH, raw)
        )
        self.assertTrue(result["accepted"])
        with self.assertRaises(ValueError):
            event_relay.forward(dict(frame, url="http://unrelated.invalid"))

    def test_invalid_and_oversized_frames_never_reach_http(self):
        output = io.BytesIO()
        with patch.object(event_relay, "forward") as forward:
            event_relay.serve(io.BytesIO(b"x" * (event_relay.MAX_FRAME + 1)), output)
            forward.assert_not_called()
        output = io.BytesIO()
        event_relay.serve(io.BytesIO(b"{}\n"), output)
        self.assertEqual(json.loads(output.getvalue())["status"], 400)


if __name__ == "__main__":
    unittest.main()
