"""Restricted SSH forced-command relay to a loopback-only Router HTTP API.

Install this file on the receiving host. Only the fixed events path is exposed;
neither URLs nor commands can be selected by incoming frames. Standard library only.
"""

import argparse
import base64
import http.client
import json
import re
import sys

PATH = "/wechat-router/v1/events"
MAX_BODY = 128 * 1024
MAX_FRAME = 192 * 1024


def forward(frame, port=8768):
    if set(frame) != {"body", "timestamp", "signature"}:
        raise ValueError("invalid frame")
    body = base64.b64decode(frame["body"], validate=True)
    stamp = frame["timestamp"]
    signature = frame["signature"]
    if (
        len(body) > MAX_BODY
        or not re.fullmatch(r"[0-9]{1,16}", stamp)
        or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature)
    ):
        raise ValueError("invalid frame")
    event_id = json.loads(body)["event_id"]
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request(
            "POST",
            PATH,
            body,
            {
                "Content-Type": "application/json",
                "X-Wechat-Router-Timestamp": stamp,
                "X-Wechat-Router-Signature": signature,
            },
        )
        reply = connection.getresponse()
        raw = reply.read(MAX_BODY + 1)
        try:
            value = json.loads(raw) if len(raw) <= MAX_BODY else {}
        except (ValueError, UnicodeError):
            value = {}
        if not isinstance(value, dict):
            value = {}
        return {
            "status": reply.status,
            "accepted": reply.status in (200, 202)
            and value.get("event_id") == event_id,
            "event_id": event_id,
            "retry_after": reply.getheader("Retry-After"),
        }
    finally:
        connection.close()


def serve(input_stream, output_stream, port=8768):
    while True:
        line = input_stream.readline(MAX_FRAME + 1)
        if not line:
            return
        if len(line) > MAX_FRAME or not line.endswith(b"\n"):
            return
        try:
            response = forward(json.loads(line), port)
        except (ValueError, KeyError, TypeError):
            response = {"status": 400, "accepted": False}
        except Exception:
            response = {"status": 503, "accepted": False}
        output_stream.write(
            json.dumps(response, separators=(",", ":")).encode() + b"\n"
        )
        output_stream.flush()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8768)
    serve(sys.stdin.buffer, sys.stdout.buffer, parser.parse_args().port)
