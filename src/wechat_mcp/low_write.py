"""Opt-in resident sync: encrypted files -> memory -> conditional index writes.

No decrypted database or polling heartbeat is written to disk. Legacy CLI and
short-lived stdio hosts retain their original disk sync path.
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
import struct
import threading
import time
from pathlib import Path

from .sources import MemorySource, memory_connection, publish

SYNC_LOCK = threading.Lock()
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
VERIFY_INTERVAL_SECONDS = 300
_cache = {}


def enabled():
    return os.environ.get("WECHAT_SYNC_MODE", "").lower() == "memory"


def _checksum(data, state=(0, 0), endian="<"):
    s0, s1 = state
    for a, b in struct.iter_unpack(endian + "II", data):
        s0 = (s0 + a + s1) & 0xFFFFFFFF
        s1 = (s1 + b + s0) & 0xFFFFFFFF
    return s0, s1


def validate_image(image):
    conn = memory_connection(image)
    try:
        try:
            if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("Decrypted snapshot failed integrity check")
        except sqlite3.OperationalError as exc:
            # WCDB FTS tables reference tokenizers unavailable in stock SQLite.
            # Restrict the fallback to SQLITE_ERROR plus an explicit custom FTS
            # tokenizer. CORRUPT/NOTADB/IOERR and other failures remain fatal.
            tables = conn.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='table'"
            ).fetchall()
            custom = any(
                sql
                and "CREATE VIRTUAL TABLE" in sql.upper()
                and re.search(r"tokenize\s*=\s*['\"]?MMFtsTokenizer\b", sql, re.I)
                for _, sql in tables
            )
            if (
                getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_ERROR
                or not custom
            ):
                raise
            # Partial checks exclude the virtual table itself, whose xIntegrity
            # requires the unavailable tokenizer. Ordinary and shadow b-trees
            # are still checked, including constraints and indexes.
            for name, sql in [("sqlite_schema", "")] + tables:
                if sql and "CREATE VIRTUAL TABLE" in sql.upper():
                    continue
                quoted = name.replace('"', '""')
                rows = conn.execute(f'PRAGMA integrity_check("{quoted}")').fetchall()
                if rows != [("ok",)]:
                    raise ValueError("Decrypted table failed integrity check")
    finally:
        conn.close()


def decrypt_image(encrypted, wal, key):
    """Authenticate WCDB pages; replay only a valid, committed WAL prefix."""
    from .tools import key_tool as kt

    page_size = kt.PAGE_SZ
    if not encrypted or len(encrypted) % page_size:
        raise ValueError("Incomplete encrypted database")
    salt = encrypted[: kt.SALT_SZ]
    mac_key = hashlib.pbkdf2_hmac(
        "sha512", key, bytes(b ^ 0x3A for b in salt), 2, dklen=kt.KEY_SZ
    )

    def decode(page, number):
        start = kt.SALT_SZ if number == 1 else 0
        message = page[start : page_size - kt.RESERVE_SZ + kt.IV_SZ]
        digest = hmac.new(
            mac_key, message + struct.pack("<I", number), hashlib.sha512
        ).digest()
        if not hmac.compare_digest(digest, page[page_size - kt.HMAC_SZ : page_size]):
            raise ValueError("Encrypted page authentication failed")
        return kt._decrypt_page(key, page, number)

    image = bytearray()
    for offset in range(0, len(encrypted), page_size):
        image.extend(
            decode(encrypted[offset : offset + page_size], offset // page_size + 1)
        )
    if wal:
        if len(wal) < 32:
            raise ValueError("Incomplete WAL header; retry later")
        magic, version, wal_size = struct.unpack(">III", wal[:12])
        if (
            magic not in (0x377F0682, 0x377F0683)
            or version != 3007000
            or wal_size != page_size
        ):
            raise ValueError("Unsupported WAL header")
        endian = "<" if magic == 0x377F0682 else ">"
        state = _checksum(wal[:24], endian=endian)
        if state != struct.unpack(">II", wal[24:32]):
            raise ValueError("Invalid WAL header checksum")
        pending = []
        committed = []
        db_pages = 0
        for offset in range(32, len(wal) - (24 + page_size) + 1, 24 + page_size):
            frame = wal[offset : offset + 24 + page_size]
            number, size = struct.unpack(">II", frame[:8])
            # Old frames can remain after WAL reuse. A mismatching tail is not
            # part of this generation; never scan beyond it looking for commits.
            if number == 0 or frame[8:16] != wal[16:24]:
                break
            candidate = _checksum(frame[:8] + frame[24:], state, endian)
            if candidate != struct.unpack(">II", frame[16:24]):
                break
            state = candidate
            if (
                number * page_size > MAX_DATABASE_BYTES
                or size * page_size > MAX_DATABASE_BYTES
            ):
                raise ValueError("WAL exceeds database memory limit")
            pending.append((number, decode(frame[24:], number)))
            if size:
                committed.extend(pending)
                pending.clear()
                db_pages = size
        for number, page in committed:
            if number > db_pages:
                continue
            if len(image) < number * page_size:
                image.extend(b"\0" * (number * page_size - len(image)))
            image[(number - 1) * page_size : number * page_size] = page
        if db_pages:
            del image[db_pages * page_size :]
    # A self-contained image has no SQLite sidecar. deserialize cannot open a
    # WAL-mode image requiring a filesystem WAL, so normalize journal markers.
    image[18:20] = b"\x01\x01"
    result = bytes(image)
    validate_image(result)
    return result


def _file_state(path, header_size):
    try:
        with path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            header = stream.read(header_size)
        return (
            stat.st_dev,
            stat.st_ino,
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            header,
        )
    except FileNotFoundError:
        return None


def scan(directory):
    return {
        p.relative_to(directory).as_posix(): (
            _file_state(p, 96),
            _file_state(Path(str(p) + "-wal"), 32),
        )
        for p in sorted(directory.rglob("*.db"))
    }


def _read_bounded(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_DATABASE_BYTES + 1)
    if len(data) > MAX_DATABASE_BYTES:
        raise ValueError("Source file exceeds memory limit")
    return data


class SnapshotCache:
    def __init__(self):
        self.states = {}
        self.images = {}
        self.key_digest = None
        self.verified_at = 0
        self.index_identity = None

    def prepare(self, directory, keys_bytes, root, force=False, decoder=None):
        from .tools.key_tool import _get_key_info, _strip_key_metadata

        decoder = decoder or decrypt_image
        key_digest = hashlib.sha256(keys_bytes).digest()
        keys = _strip_key_metadata(json.loads(keys_bytes))
        full = (
            force
            or key_digest != self.key_digest
            or time.monotonic() - self.verified_at >= VERIFY_INTERVAL_SECONDS
        )
        for attempt in range(3):
            states = scan(directory)
            if not states:
                raise ValueError("No source databases found")
            images = {
                name: data for name, data in self.images.items() if name in states
            }
            for name, state in states.items():
                if not full and self.states.get(name) == state and name in images:
                    continue
                info = _get_key_info(keys, name)
                if info is None:
                    raise ValueError(
                        "A source database has no saved key; initialize keys again"
                    )
                path = directory / name
                encrypted = _read_bounded(path)
                wal_path = Path(str(path) + "-wal")
                try:
                    wal = _read_bounded(wal_path)
                except FileNotFoundError:
                    wal = b""
                images[name] = decoder(encrypted, wal, bytes.fromhex(info["enc_key"]))
                if sum(map(len, images.values())) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Snapshot exceeds memory limit")
            if states == scan(directory):
                changed = {
                    name
                    for name, image in images.items()
                    if self.images.get(name) != image
                }
                removed = set(self.images) - set(images)
                # Contact display names also feed the session projection.
                selected = set(changed)
                if any(n.startswith("contact/") for n in changed):
                    selected.update(n for n in images if n.startswith("session/"))
                return (
                    MemorySource(root, images, selected),
                    states,
                    key_digest,
                    changed,
                    removed,
                    full,
                )
        raise RuntimeError("Source changed during capture; previous snapshot retained")

    def accept(self, candidate, states, key_digest, full):
        self.images = candidate.images
        self.states = states
        self.key_digest = key_digest
        if full:
            self.verified_at = time.monotonic()
        publish(candidate)


def sync_memory(force=False, redecrypt=True):
    from .config import USER_WECHAT_DIR, get_decrypted_dir
    from .database import sync_memory_source
    from .auto_sync import _db_dir_from_keys

    if not SYNC_LOCK.acquire(blocking=False):
        return {"ok": True, "etl_step": {"status": "busy"}}
    try:
        keys_path = USER_WECHAT_DIR / "all_keys.json"
        directory = os.environ.get("WECHAT_DB_DIR") or _db_dir_from_keys(keys_path)
        if not directory or not Path(directory).is_dir():
            raise ValueError("Source database directory unavailable")
        directory = Path(directory).resolve()
        root = get_decrypted_dir().resolve()
        cache = _cache.setdefault((directory, root), SnapshotCache())
        if not redecrypt:
            if not cache.images:
                raise ValueError("No resident snapshot; run a full sync first")
            candidate = MemorySource(root, cache.images)
            result = sync_memory_source(candidate)
            from .events import notify_committed

            notify_committed()
            return {"ok": True, "etl_step": result}
        candidate, states, digest, changed, removed, full = cache.prepare(
            directory, keys_path.read_bytes(), root, force
        )
        # Memory mode targets the WCDB 4.x directory layout. Do not silently
        # publish an empty index for older layouts.
        if not any(
            n.startswith(("message/", "contact/", "session/")) for n in candidate.images
        ):
            raise ValueError("Memory sync currently supports WeChat 4.x layout only")
        from .config import DB_PATH

        identity = _file_state(DB_PATH, 0)
        identity = identity[:2] if identity else None
        rebuild = force or cache.index_identity != identity or identity is None
        if rebuild:
            candidate.selected = set(candidate.images)
        if changed or removed or rebuild:
            result = sync_memory_source(candidate, removed)
        else:
            result = {"status": "skipped", "changed_rows": 0}
        cache.accept(candidate, states, digest, full)
        if changed or removed or rebuild:
            from .events import notify_committed

            notify_committed()
        identity = _file_state(DB_PATH, 0)
        cache.index_identity = identity[:2] if identity else None
        return {
            "ok": True,
            "decrypt_step": {
                "ok": True,
                "mode": "memory",
                "changed_databases": len(changed),
                "removed_databases": len(removed),
            },
            "etl_step": result,
        }
    except Exception as exc:
        # Keep diagnostic details local; source errors can include private data.
        import logging

        logging.getLogger(__name__).debug("Memory sync failed", exc_info=True)
        return {
            "ok": False,
            "error": type(exc).__name__
            + ": snapshot update failed; previous data retained",
        }
    finally:
        SYNC_LOCK.release()
