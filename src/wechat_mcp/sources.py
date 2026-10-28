"""Read-only database sources shared by ETL and tools needing original payloads."""

import sqlite3
import threading
from pathlib import Path


class DiskSource:
    strict = False

    def exists(self, path):
        return Path(path).exists()

    def files(self, directory):
        return Path(directory).glob("*.db")

    def connect(self, path):
        return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)


class MemorySource:
    strict = True

    def __init__(self, root, images, selected=None):
        self.root = Path(root).resolve()
        self.images = images
        self.selected = set(images) if selected is None else set(selected)
        self.connections = []

    def relative(self, path):
        return Path(path).resolve().relative_to(self.root).as_posix()

    def exists(self, path):
        rel = self.relative(path)
        if rel == ".":
            return True
        if rel.endswith(".db"):
            return rel in self.selected
        return any(name.startswith(rel + "/") for name in self.images)

    def files(self, directory):
        rel = self.relative(directory)
        return [
            self.root / name
            for name in sorted(self.selected)
            if Path(name).parent.as_posix() == rel
        ]

    def connect(self, path):
        conn = memory_connection(self.images[self.relative(path)])
        self.connections.append(conn)
        return conn

    def close(self):
        for conn in self.connections:
            conn.close()
        self.connections.clear()


def memory_connection(image):
    if not hasattr(sqlite3.Connection, "deserialize"):
        raise RuntimeError(
            "Memory sync requires SQLite deserialize support (Python 3.11+)"
        )
    conn = sqlite3.connect(":memory:")
    try:
        conn.deserialize(image)
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA query_only=ON")
        return conn
    except Exception:
        conn.close()
        raise


_published = None
_publication_lock = threading.RLock()


def publish(source):
    global _published
    # The map and its bytes are immutable after publication. Each reader gets
    # an independent SQLite connection and pins that generation's byte buffer.
    with _publication_lock:
        _published = MemorySource(source.root, source.images)


def published_for(path):
    with _publication_lock:
        source = _published
        if source is not None:
            try:
                source.relative(path)
                return source
            except ValueError:
                pass
    return None


def source_exists(path):
    source = published_for(path)
    return source.exists(path) if source else Path(path).exists()


def connect_source(path):
    source = published_for(path)
    if source:
        return memory_connection(source.images[source.relative(path)])
    return DiskSource().connect(path)
