"""Avoid SQLite writes, AUTOINCREMENT churn and FTS triggers for identical rows."""


def upsert(cur, table, columns, keys, spec, params, fill_empty=False):
    # All identifiers/specs are literals in our adapters, never source payloads.
    args = iter(params)
    values = tuple(next(args) if token == "?" else token for token in spec)
    positions = [columns.index(key) for key in keys]
    key_values = tuple(values[i] for i in positions)
    if table == "messages" and hasattr(cur, "seen_messages"):
        cur.seen_messages.add(key_values)
    predicate = " AND ".join(f"{key} IS ?" for key in keys)
    row = cur.execute(
        f"SELECT {', '.join(columns)} FROM {table} WHERE {predicate}", key_values
    ).fetchone()
    if row is not None:
        old = tuple(row)
        if fill_empty:
            values = tuple(
                (
                    new
                    if col in ("caption", "package_id", "package_name") and before == ""
                    else before
                )
                for col, before, new in zip(columns, old, values)
            )
        changed = [
            i
            for i, (before, after) in enumerate(zip(old, values))
            if before != after and columns[i] not in keys
        ]
        if not changed:
            return False
        assignments = ", ".join(f"{columns[i]} = ?" for i in changed)
        cur.execute(
            f"UPDATE {table} SET {assignments} WHERE {predicate}",
            tuple(values[i] for i in changed) + key_values,
        )
    else:
        cur.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
            values,
        )
    return True


def upsert_empty(cur, table, columns, keys, spec, params):
    return upsert(cur, table, columns, keys, spec, params, fill_empty=True)
