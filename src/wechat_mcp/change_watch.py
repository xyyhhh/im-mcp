"""OS change notifications, coalesced into one resident synchronization task."""

import threading
import time
from pathlib import Path


def relevant_event(event):
    if event.event_type not in {"created", "modified", "deleted", "moved"}:
        return False
    if event.is_directory:
        return True
    return any(
        str(path).lower().endswith((".db", ".db-wal", "all_keys.json"))
        for path in (event.src_path, getattr(event, "dest_path", ""))
    )


class ChangeWatch:
    """Watchdog uses ReadDirectoryChangesW on Windows, inotify on Linux."""

    def __init__(self, directory, keys_path):
        self.directory = Path(directory)
        self.keys_path = Path(keys_path)
        self.event = threading.Event()
        self.observer = None
        self.mode = "polling-fallback"

    def start(self):
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        wake = self.event

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                if relevant_event(event):
                    wake.set()

        keys_path = self.keys_path.resolve()

        class KeyHandler(FileSystemEventHandler):
            def on_any_event(self, event):
                if event.event_type not in {"created", "modified", "deleted", "moved"}:
                    return
                paths = (event.src_path, getattr(event, "dest_path", ""))
                if any(path and Path(path).resolve() == keys_path for path in paths):
                    wake.set()

        observer = Observer()
        try:
            observer.schedule(Handler(), str(self.directory), recursive=True)
            observer.schedule(KeyHandler(), str(self.keys_path.parent), recursive=False)
            observer.start()
        except Exception:
            observer.stop()
            if observer.is_alive():
                observer.join(timeout=2)
            raise
        self.observer = observer
        self.mode = "filesystem-events"

    def wait(self, stop, verification_seconds=300):
        # A short wait only checks an in-memory flag, not database files.
        deadline = time.monotonic() + verification_seconds
        while not stop.is_set():
            if self.event.wait(min(0.25, max(0, deadline - time.monotonic()))):
                self.event.clear()
                # Quiet-period debounce with a hard cap under continuous writes.
                cap = time.monotonic() + 2
                while time.monotonic() < cap and not stop.is_set():
                    if not self.event.wait(min(0.3, cap - time.monotonic())):
                        return True
                    self.event.clear()
                return not stop.is_set()
            if time.monotonic() >= deadline:
                return True
        return False

    def close(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
