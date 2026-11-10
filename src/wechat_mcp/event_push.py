"""Opt-in durable Router delivery through a restricted, authenticated SSH relay."""

import atexit
import base64
from contextlib import closing
import datetime
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import queue
import random
import re
import sqlite3
import subprocess
import threading
import time

from . import events
from .event_relay import PATH, MAX_BODY

logger = logging.getLogger(__name__)
_worker = None


def signed_frame(body, secret, timestamp=None):
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    prefix = f"v1\n{stamp}\nPOST\n{PATH}\n".encode()
    return {
        "timestamp": stamp,
        "signature": "sha256="
        + hmac.new(secret.encode(), prefix + body, hashlib.sha256).hexdigest(),
        "body": base64.b64encode(body).decode("ascii"),
    }


class SSHRelay:
    def __init__(self, settings):
        host = str(ipaddress.ip_address(settings["host"]))
        user = settings["user"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", user):
            raise ValueError("Invalid relay account")
        port = int(settings["port"])
        if not 1 <= port <= 65535:
            raise ValueError("Invalid relay port")
        self.command = [
            settings["executable"],
            "-F",
            "none",
            "-T",
            "-p",
            str(port),
            "-i",
            settings["identity_file"],
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + settings["known_hosts"],
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            user + "@" + host,
        ]
        self.process = None
        self.responses = None

    @staticmethod
    def _reader(process, responses):
        try:
            while True:
                line = process.stdout.readline(4097)
                if not line or len(line) > 4096 or not line.endswith(b"\n"):
                    break
                responses.put(json.loads(line))
        except Exception:
            pass
        finally:
            responses.put(None)

    def send(self, frame):
        if self.process is None or self.process.poll() is not None:
            self.close()
            self.responses = queue.Queue()
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            threading.Thread(
                target=self._reader, args=(self.process, self.responses), daemon=True
            ).start()
        try:
            self.process.stdin.write(
                json.dumps(frame, separators=(",", ":")).encode() + b"\n"
            )
            self.process.stdin.flush()
            result = self.responses.get(timeout=30)
            if not isinstance(result, dict):
                raise ConnectionError("Relay disconnected")
            return result
        except Exception:
            self.close()
            raise

    def close(self):
        process, self.process = self.process, None
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def message_mentions(snapshot):
    """Best-effort source lookup; absent mentions are never inferred from names."""
    from .config import get_decrypted_dir
    from .parser import maybe_zstd_decompress, extract_tag_from_xml
    from .sources import connect_source, source_exists

    name = snapshot.get("source_file", "")
    if not name or Path(name).name != name:
        return []
    path = get_decrypted_dir() / "message" / name
    if not source_exists(path):
        return []
    table = "Msg_" + hashlib.md5(snapshot["session_username"].encode()).hexdigest()
    try:
        with closing(connect_source(path)) as conn:
            row = conn.execute(
                f'SELECT source FROM "{table}" WHERE local_id=? AND create_time=?',
                (snapshot["local_id"], snapshot["create_time"]),
            ).fetchone()
        text = maybe_zstd_decompress(row[0]) if row and row[0] else ""
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="replace")
        values = extract_tag_from_xml(text, "atuserlist").split(",")
        return list(
            dict.fromkeys(
                v.strip()
                for v in values
                if v.strip()
                and len(v.strip()) <= 256
                and not any(ord(c) < 32 for c in v)
            )
        )[:100]
    except (sqlite3.Error, KeyError, TypeError):
        return []


class Delivery:
    def __init__(self, database, settings, transport=None):
        self.database = Path(database)
        self.settings = settings
        self.stop = threading.Event()
        self.transport = transport
        self.thread = None

    def connection(self):
        conn = sqlite3.connect(self.database, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        baseline = self.settings["start_after_event_id"]
        if type(baseline) is not int or baseline < 0:
            raise ValueError("Invalid first-delivery watermark")
        if not self.settings.get("owner_ids") or not self.settings.get("source"):
            raise ValueError("Explicit owner IDs and source are required")
        with closing(self.connection()) as conn:
            events.ensure_schema(conn)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS event_push_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS event_push_outbox(
                    event_id TEXT PRIMARY KEY, body BLOB, state TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0, last_status INTEGER);
            """)
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO event_push_meta VALUES('start_after',?)",
                    (str(baseline),),
                )
                self.baseline = int(
                    conn.execute(
                        "SELECT value FROM event_push_meta WHERE key='start_after'"
                    ).fetchone()[0]
                )

    def pending(self):
        with closing(self.connection()) as conn:
            return [
                dict(row)
                for row in conn.execute(
                    """
                SELECT e.* FROM message_events e LEFT JOIN event_push_outbox o ON o.event_id=e.event_id
                WHERE e.acknowledged=0 AND e.id>? AND COALESCE(o.state,'pending')='pending'
                ORDER BY e.id LIMIT 100""",
                    (self.baseline,),
                )
            ]

    def freeze(self, event):
        with closing(self.connection()) as conn:
            saved = conn.execute(
                "SELECT body FROM event_push_outbox WHERE event_id=?",
                (event["event_id"],),
            ).fetchone()
            if saved is not None and saved[0] is not None:
                return saved[0]
            snapshot = json.loads(event["snapshot"] or "null")
            if not isinstance(snapshot, dict):
                raise ValueError("Event has no immutable snapshot")
            conversation, sender = (
                snapshot["session_username"],
                snapshot["sender_username"],
            )
            if not conversation or not sender:
                raise ValueError("Event identity missing")

            def label(table, identity):
                row = conn.execute(
                    f"SELECT display_name FROM {table} WHERE username=?", (identity,)
                ).fetchone()
                return str(row[0] or identity)[:256] if row else str(identity)[:256]

            epoch = snapshot["create_time"]
            epoch = epoch / 1000 if epoch > 10**11 else epoch
            text = snapshot.get("content") or ""
            base = snapshot["local_type"] & 0xFFFFFFFF
            subtype = snapshot["local_type"] >> 32
            kind = {
                1: "text",
                3: "image",
                34: "voice",
                43: "video",
                10000: "system",
            }.get(base, "other")
            if base == 49:
                kind = "file" if subtype == 6 else "text" if subtype == 57 else "link"
            payload = {
                "source": self.settings["source"],
                "event_id": event["event_id"],
                "conversation_id": conversation,
                "chat_type": "group" if conversation.endswith("@chatroom") else "dm",
                "conversation_name": label("sessions", conversation),
                "sender_id": sender,
                "sender_name": label("contacts", sender),
                "occurred_at": datetime.datetime.fromtimestamp(
                    epoch, datetime.timezone.utc
                ).isoformat(),
                "message_type": kind,
                "is_self": sender in self.settings["owner_ids"],
                "mentions": message_mentions(snapshot),
            }
            if event["kind"] != "message.created":
                original = conn.execute(
                    "SELECT event_id FROM message_events WHERE message_id=? AND kind='message.created' ORDER BY id LIMIT 1",
                    (event["message_id"],),
                ).fetchone()
                if original:
                    payload["reply_to"] = original[0]
                text = (
                    "[消息更新] "
                    if event["kind"] == "message.updated"
                    else "[消息删除/撤回] "
                ) + text
                payload["message_type"] = (
                    "system" if event["kind"] == "message.deleted" else kind
                )
            if len(text) > 8000:
                note = f'\n[正文截断；完整内容请通过 MCP 查询消息 ID {event["message_id"]}]'
                text = text[: 8000 - len(note)] + note
            payload["text"] = text
            body = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            if len(body) > MAX_BODY:
                raise ValueError("Event exceeds receiver body limit")
            with conn:
                conn.execute(
                    "INSERT INTO event_push_outbox(event_id,body) VALUES (?,?) ON CONFLICT(event_id) DO UPDATE SET body=excluded.body",
                    (event["event_id"], body),
                )
            return body

    def block(self, event, status):
        with closing(self.connection()) as conn, conn:
            conn.execute(
                "INSERT INTO event_push_outbox(event_id,state,last_status) VALUES (?,'blocked',?) ON CONFLICT(event_id) DO UPDATE SET state='blocked',last_status=excluded.last_status",
                (event["event_id"], status),
            )
        logger.warning(
            "Event delivery blocked (queue_id=%s, status=%s); retained for review",
            event["id"],
            status,
        )

    def deliver(self, event, secret):
        try:
            body = self.freeze(event)
        except (ValueError, KeyError, TypeError):
            self.block(event, 400)
            return "blocked", None
        result = self.transport.send(signed_frame(body, secret))
        status = int(result.get("status", 503))
        accepted = (
            status in (200, 202)
            and result.get("accepted") is True
            and result.get("event_id") == event["event_id"]
        )
        with closing(self.connection()) as conn, conn:
            conn.execute(
                "UPDATE event_push_outbox SET attempts=attempts+1,last_status=? WHERE event_id=?",
                (status, event["event_id"]),
            )
            if accepted:
                conn.execute(
                    "UPDATE event_push_outbox SET state='sent',body=NULL WHERE event_id=?",
                    (event["event_id"],),
                )
                conn.execute(
                    "UPDATE message_events SET acknowledged=1 WHERE id=?",
                    (event["id"],),
                )
        if accepted:
            return "sent", None
        if status in (400, 401, 403, 409, 413):
            self.block(event, status)
            return "blocked", None
        retry = result.get("retry_after")
        return "retry", min(300, int(retry)) if str(retry).isdigit() else None

    def run(self):
        try:
            self.initialize()
            secret = (
                Path(self.settings["secret_file"]).read_text(encoding="utf-8").strip()
            )
            if len(secret.encode()) < 32:
                raise ValueError("Invalid delivery secret")
            self.transport = self.transport or SSHRelay(self.settings["ssh"])
            failures = 0
            while not self.stop.is_set():
                events._ready.clear()
                pending = self.pending()
                if not pending:
                    events._ready.wait()
                    continue
                for event in pending:
                    if self.stop.is_set():
                        break
                    try:
                        outcome, retry = self.deliver(event, secret)
                    except Exception:
                        outcome, retry = "retry", None
                        self.transport.close()
                        if failures == 0:
                            logger.warning(
                                "Event delivery unavailable; retaining pending events and retrying"
                            )
                    if outcome == "retry":
                        failures += 1
                        delay = (
                            retry
                            if retry is not None
                            else min(60, 2 ** min(failures, 6)) + random.random()
                        )
                        self.stop.wait(delay)
                        break
                    if failures:
                        logger.info("Event delivery recovered")
                    failures = 0
        except Exception:
            logger.error(
                "Event delivery stopped; inspect private configuration and queue; no events acknowledged"
            )
        finally:
            if self.transport:
                self.transport.close()

    def close(self):
        self.stop.set()
        events.notify_committed()
        if self.transport:
            self.transport.close()
        if self.thread:
            self.thread.join(timeout=2)


def start_from_environment():
    global _worker
    path = os.environ.get("WECHAT_EVENT_PUSH_CONFIG")
    if not path or (_worker and _worker.thread.is_alive()):
        return
    settings = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not settings.get("enabled", False):
        return
    from .config import DB_PATH

    worker = Delivery(DB_PATH, settings)
    worker.thread = threading.Thread(
        target=worker.run, name="wechat-event-push", daemon=True
    )
    worker.thread.start()
    _worker = worker
    atexit.register(worker.close)
