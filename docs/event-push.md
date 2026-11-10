# Optional durable Router delivery

Set `WECHAT_EVENT_PUSH_CONFIG` to a private JSON file to enable delivery inside
the existing resident MCP process; no additional Windows service is needed.
Without this variable there is no network delivery. Configuration failures do
not disable database synchronization.

The adapter waits for committed message-event notifications instead of polling.
A durable outbox freezes each serialized request before sending. An accepted,
matching receipt (HTTP 202 or duplicate HTTP 200) acknowledges the event in the
same transaction as its delivery result. Lost responses are retried with the
same event ID and content; only the signature timestamp changes. Confirmed
outbox bodies are cleared; pending bodies survive restarts.

## Transport

The installed OpenSSH client uses a pinned known-hosts file and dedicated key.
A persistent SSH session carries bounded JSON frames to `event_relay.py` on the
receiver. Restrict that key with an SSH forced command and `restrict`, optionally
limiting the source address. Do not grant port/agent forwarding, a PTY, user rc,
or general shell access; do not reuse an administrative key. Incoming frames
cannot choose a URL, port or command. The relay only POSTs to the fixed loopback
Router API and still requires its HMAC secret. No plaintext LAN HTTP port opens.

Copy `src/wechat_mcp/event_relay.py` to the receiving host. Its forced command is
`python3 /path/to/event_relay.py --port <router-port>`; only the existing standard
library is needed. The API is `/wechat-router/v1/events`, with Router v1 HMAC.
The receiver's `receive_only: true` mode can persist messages without a model key
or dispatcher. This adapter sends indexed text and media descriptions, not media
binaries, and never calls an AI service itself.

## Private configuration

```json
{
  "enabled": true,
  "source": "im-mcp",
  "owner_ids": ["account-id"],
  "start_after_event_id": 123,
  "secret_file": "path/to/router.secret",
  "ssh": {
    "executable": "path/to/ssh",
    "host": "192.0.2.10",
    "port": 22,
    "user": "receiver",
    "identity_file": "path/to/dedicated-key",
    "known_hosts": "path/to/pinned-known-hosts"
  }
}
```

Use an explicit SSH host IP. Protect the configuration and credentials with
service-account ACLs; keep them outside Git. The initial `start_after_event_id`
is a deliberate watermark. Set it to the highest local event ID immediately
before activation to avoid sending the historical backlog. Its persisted value
is authoritative after restart; editing configuration cannot silently drop work.

Events retain the indexed content, conversation/sender identity and source time
at the change. Edits/deletions have distinct event IDs, a descriptive prefix and
a reference to the first created event when available. These are context, not
commands to cancel tasks. Source `atuserlist` supplies mentions when available;
names are never used to guess mentions. Over 8,000 text characters are explicitly
truncated with a local MCP message-ID reference to the complete content.

## Recovery, privacy and writes

Timeouts, disconnects, 429 and temporary failures retain pending work and use
bounded exponential backoff with jitter. 400/401/403/409/413 responses retain a
blocked row for review without starving later valid events; it is not
acknowledged. Fix its cause, explicitly return its outbox state to pending, and
restart delivery. Do not change event IDs merely to bypass conflicts.

`message_events.snapshot` and `event_push_outbox` are sensitive index data.
Unlike the original metadata-only interface, new event snapshots retain message
text so edits/deletions remain deliverable after the live index changes. Freeze,
confirmation and retry state cause small transactional writes. Empty-queue waits
have no polling/heartbeat writes. Notification delivery never rewrites decoded
databases/media. Logs omit payloads, credentials and raw SSH errors. Existing
explicit pruning never deletes unacknowledged events; retention of confirmed
events and outbox metadata remains an operator policy. Only one logical consumer
is supported by the event queue's acknowledgement flag.
