"""Transport-neutral, durable message events. No network or script execution.

One logical consumer reads pending events and acknowledges only after its
downstream operation succeeds. Delivery is at least once; deduplicate by id.
Event rows contain index IDs, not message text or contact names. An initial
baseline is silent; subsequent changes, including historical imports, emit.
"""

import sqlite3
import threading

_ready = threading.Event()


def notify_committed():
    """Wake an in-process adapter after commit; never send data externally."""
    _ready.set()


def wait_for_events(timeout=None, limit=100):
    """Block on a notification, not repeated database polling (same process)."""
    _ready.clear()
    pending = pending_events(limit)
    if pending:
        return pending
    _ready.wait(timeout)
    return pending_events(limit)


def pending_events(limit=100):
    from .config import DB_PATH

    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='message_events'"
        ).fetchone()
        if not exists:
            return []
        rows = conn.execute(
            """SELECT id, event_id, kind, message_id, created_at FROM message_events
            WHERE acknowledged=0 ORDER BY id LIMIT ?""",
            (max(1, min(int(limit), 1000)),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def acknowledge_events(ids):
    from .config import DB_PATH

    ids = list(dict.fromkeys(int(value) for value in ids))
    if not ids:
        return
    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.executemany(
                "UPDATE message_events SET acknowledged=1 WHERE id=? AND acknowledged=0",
                ((value,) for value in ids),
            )
    finally:
        conn.close()


def prune_events(before_timestamp):
    """Explicit maintenance: never discard pending events to enforce a cap."""
    from .config import DB_PATH

    conn = sqlite3.connect(DB_PATH)
    try:
        with conn:
            conn.execute(
                "DELETE FROM message_events WHERE acknowledged=1 AND created_at<?",
                (int(before_timestamp),),
            )
    finally:
        conn.close()
