# Tool reference

All nine tools registered by `drill-mcp` (see
[`drill_mcp/server.py`](../drill_mcp/server.py)). Every tool raises a single
exception type, `ToolError`, to the MCP client — never a raw traceback, never
an unrelated Python exception. `ToolError`'s message is the only thing a
model sees; where the underlying failure is Drill's own error text, that
text is passed through (and truncated at 2000 characters — see
[`client_rest.py`](../drill_mcp/client_rest.py)`_error_text`).

Five of the nine tools (`list_storage_plugins`, `cluster_status`,
`list_profiles`, `get_profile`, `cancel_query`) are **management tools**:
they require the REST backend. On the JDBC backend they all raise the same
`ToolError`:

```
'<method>' needs a REST connection to Drill; the JDBC backend does not
expose management endpoints
```

This is because `JdbcClient` (`drill_mcp/client_jdbc.py`) simply does not
implement `storage_plugins`, `cluster_status`, `profiles`, `profile`, or
`cancel_query` — there is no fallback or emulation attempted.

---

## `run_query`

```
run_query(sql: str, max_rows: int | None = None) -> dict
```

Runs exactly one SQL statement against Drill and returns its rows.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `sql` | string | no | Exactly one SQL statement. Anything that doesn't parse as one statement is rejected — see "Safety" below. |
| `max_rows` | integer | yes (default `None`) | A cap on returned rows. May only *lower* the server's configured `max_rows`, never raise it (see below). A value `<= 0` is treated as "not supplied" and the configured cap is used. |

**Returns** a dict:

```json
{
  "columns": ["id", "name"],
  "rows": [{"id": 1, "name": "alice"}],
  "query_id": "24680246-1000-abcd-8888-0123456789ab",
  "truncated": false
}
```

If the result was truncated, a `"note"` key is added:

```json
{
  "truncated": true,
  "note": "Results were truncated at 100 rows. Narrow the query or aggregate to see the rest."
}
```

`query_id` is Drill's own query UUID on the REST backend, useful as input to
`get_profile`/`cancel_query`. **On the JDBC backend `query_id` is always
`null`** — `JdbcClient.query` has no way to recover it from a plain JDBC
cursor, so `get_profile`/`cancel_query` are of no use for a query run
through JDBC even independent of their REST-only restriction.

**Errors**

- `sql must be a string` — `sql` was not a `str`.
- `max_rows must be an integer` — `max_rows` was supplied but not an `int`.
- Any policy rejection (see "Safety" below) — message explains which rule
  was violated (unwritable plugin, hidden schema, multiple statements,
  disallowed statement type, unparseable SQL).
- Drill's own error text (e.g. `VALIDATION ERROR: no such table`), passed
  through from `DrillError` unchanged, truncated at 2000 characters.

**Row cap.** The effective cap is `min(max_rows, config.max_rows)` when
`max_rows` is a positive integer, otherwise `config.max_rows`. A caller
cannot ask for more rows than the operator configured; it can only ask for
fewer.

### Safety (the SQL policy)

Every statement is parsed with `sqlglot`'s Drill dialect — a real parser,
not a regex — before it reaches Drill. The policy is deny-by-default:

- **Reads are always permitted** (`SELECT`, set operations, subqueries), as
  long as no write is embedded inside them (e.g. a `WITH x AS (INSERT ...)
  SELECT * FROM x`, or a nested `CREATE`/`DROP`/`INSERT`/`UPDATE`/`DELETE`/
  `MERGE` anywhere in the parse tree — checked structurally, not textually).
- **`CREATE TABLE AS`, `CREATE VIEW`, `DROP TABLE`, `DROP VIEW`** are
  permitted only when their target is schema-qualified and that schema
  matches an entry in `writable_plugins` (see
  [`docs/configuration.md`](configuration.md)). An unqualified target (no
  `schema.` prefix) is always rejected, since there is nothing to check it
  against. `CREATE`/`DROP` of anything other than `TABLE`/`VIEW` (e.g. a
  schema or function) is rejected outright.
- **`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `ALTER`, `USE`, `REFRESH`** are
  always rejected — `writable_plugins` has no effect on them. There is no
  configuration path that permits them.
- **`ALTER SYSTEM` and storage-plugin creation/update/deletion are not
  implemented anywhere in this codebase.** There is no flag, config key, or
  hidden code path that turns them on — nothing exists for such a tool call
  to reach.
- **`SHOW` and `DESCRIBE`** are always permitted (metadata-only).
- **`EXPLAIN` / `EXPLAIN PLAN FOR` recurses.** The guard strips the leading
  keyword and re-checks the remaining statement text against the same rules
  (so `EXPLAIN` cannot be used to peek at or run a statement that would
  otherwise be rejected). Recursion is bounded (5 levels), so a
  pathological `EXPLAIN EXPLAIN EXPLAIN ...` chain cannot exhaust the stack
  — it is rejected instead.
- **Exactly one statement per call.** `sql` must parse to exactly one
  statement; stacked statements (`SELECT 1; SELECT 2`) are rejected.
- **Anything that fails to parse is rejected**, including a tokenizer
  failure (pathologically deep nesting, unterminated quoting, etc.) — a
  parse failure is never treated as "unknown, so allow it."

### Hidden schemas and `SHOW`

If `hidden_schemas` is configured, `run_query` additionally:

1. **Rejects, before the query ever reaches Drill**, any statement whose
   parsed table references resolve into a hidden schema (e.g.
   `SELECT * FROM sys.options` with `hidden_schemas: [sys]`). This applies
   to ordinary `SELECT`/`CREATE`/`DROP` statements, where sqlglot can
   identify the table references structurally.
2. **Also scans the raw text of any `SHOW`/`DESCRIBE`-style command** for a
   hidden schema's name as a whole word (sqlglot has no dedicated grammar
   for Drill's `SHOW`, so the whole command falls back to an opaque
   `Command` node with everything after the keyword left as unparsed text;
   this regex scan is a best-effort, word-boundary text match over that
   remainder, and is documented in code as a target for replacement should
   Drill's grammar ever expose `SHOW`'s target as a real expression).
3. **Filters the result rows of *every* `SHOW` command** — not just `SHOW
   SCHEMAS`/`SHOW DATABASES` — dropping any row whose first column matches
   a hidden-schema prefix. This is deliberate and fail-closed: three
   narrower attempts to detect specifically-schema-listing `SHOW` variants
   (a regex over the raw SQL, exact match against sqlglot's parsed literal,
   a comment-stripping regex over that literal) were each defeated by some
   spelling (an embedded comment, `LIKE '...'` clauses, unbalanced comment
   delimiters) and leaked a hidden schema name through. The trade-off: a
   `SHOW TABLES`/`SHOW FILES` row for a real table or file that happens to
   be *named* after a hidden-schema prefix (e.g. a table literally called
   `sys` in a workspace, under `hidden_schemas: [sys]`) is also dropped,
   even though it isn't a schema at all. A false positive here — a real
   table briefly missing from a listing — is accepted in exchange for never
   leaking a schema name the operator asked to hide.

**Hiding `INFORMATION_SCHEMA` does not break `list_schemas`, `list_tables`,
or `describe_table`.** All three query `INFORMATION_SCHEMA` internally
regardless of what's hidden; they simply omit hidden entries from what they
return to the caller.

---

## `list_schemas`

```
list_schemas() -> list[dict]
```

Lists every schema visible on the cluster, minus any matching
`hidden_schemas`.

**Parameters:** none.

**Returns** a list of dicts, one per schema:

```json
[
  {"name": "dfs.tmp", "type": "file"},
  {"name": "sys", "type": "system-tables"}
]
```

`type` is Drill's `INFORMATION_SCHEMA.SCHEMATA.TYPE` column, unmodified.

**Errors:** Drill's own error text on a connection or query failure.

---

## `list_tables`

```
list_tables(schema: str) -> list[dict]
```

Lists the tables (and, for file plugins, files/directories) in one schema.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `schema` | string | no | A dotted schema/workspace path, e.g. `dfs.tmp`. |

**Returns** a list of dicts:

```json
[
  {"name": "orders", "type": "TABLE"},
  {"name": "sales_view", "type": "VIEW"},
  {"name": "logs", "type": "DIRECTORY"}
]
```

**Behavior an operator should expect:** for a **file-based plugin**
(storage plugin `TYPE = file`, e.g. `dfs`, `s3`), `list_tables` uses `SHOW
FILES FROM <schema>` instead of `INFORMATION_SCHEMA.TABLES` — file plugins
do not register their contents in `INFORMATION_SCHEMA` at all, so querying
`TABLES` for one would silently return an empty list that looks like an
empty workspace. Under `SHOW FILES`:

- A file named `<name>.view.drill` is reported as `{"name": "<name>",
  "type": "VIEW"}` — the `.view.drill` suffix (how Drill persists a view on
  a filesystem workspace) is stripped.
- Anything Drill's directory listing marks `isDirectory: true` is reported
  as `"type": "DIRECTORY"`, not `"TABLE"`.
- Results are sorted by name.

For any other plugin type, `INFORMATION_SCHEMA.TABLES` is queried directly
and `type` is whatever `TABLE_TYPE` reports (typically `TABLE` or `VIEW`).

**Errors**

- `schema '<x>' is hidden by configuration` — `schema` matches a
  `hidden_schemas` entry. Refused before any query is issued.
- Drill's own error text otherwise.

---

## `describe_table`

```
describe_table(schema: str, table: str) -> list[dict]
```

Lists one table's columns, with type and (where determinable) nullability.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `schema` | string | no | Dotted schema/workspace path. |
| `table` | string | no | Table/view/file name. May itself contain a literal `.` (e.g. `sales.csv` on a file plugin) — treated as one identifier, not a nested path. |

**Returns** a list of dicts:

```json
[
  {"name": "id", "data_type": "INTEGER", "nullable": true},
  {"name": "created_at", "data_type": "TIMESTAMP", "nullable": null}
]
```

**Behavior an operator should expect — this is the most surprising tool in
the package.** The strategy depends on the storage plugin's `TYPE`, read
from `INFORMATION_SCHEMA.SCHEMATA` (an extra round trip on every call):

- **Static-schema plugins** (anything not `file`, `mongo`, or `splunk`):
  uses `DESCRIBE <schema>.<table>`. Metadata-only, never reads user data.
  Reports real nullability (`IS_NULLABLE` from Drill).
- **Dynamic-schema plugins** (`file`, `mongo`, `splunk`): `DESCRIBE` cannot
  answer for these — Drill discovers their schema at read time, not from a
  registry. `describe_table` instead **probes with `SELECT * FROM
  <schema>.<table> LIMIT 1`** (or, for `mongo` specifically, `SELECT \`**\`
  FROM <schema>.<table> LIMIT 1`, since Mongo's dynamic-field syntax differs
  from a plain `*`). Only the probe's **column names and types** are used;
  the sampled row's actual values are never read out of the response and
  never appear in the tool's output, under any failure mode. **Nullability
  cannot be determined from one sampled row** — a `NULL` in the one row says
  nothing about whether the column *can* be non-null, and vice versa — so
  `nullable` is reported as `null` (not guessed) on this path.
  - If the probe returns **zero rows** (e.g. the table is genuinely empty),
    `describe_table` raises rather than silently returning `[]` — an empty
    column list would be indistinguishable from "this table has no
    columns," which is a different and misleading claim.
- **HTTP plugins** (`TYPE = http`): Drill has no schema for an HTTP source
  until a real request has been made against it — there is nothing to
  `DESCRIBE` and nothing to probe. `describe_table` raises a `ToolError`
  that says so explicitly and suggests running `SELECT * FROM
  <schema>.<table> LIMIT 10` and reading the column names from the result,
  rather than returning an empty list that would look like "no columns."

**Errors**

- `schema '<x>' is hidden by configuration` — refused before any query.
- `invalid identifier: '<x>'` — `table` contains characters outside the safe
  set (letters, digits, `_`, `$`, `.`, `-`), or an unsafe `.`-segment (empty,
  or `..`, which could otherwise reach a parent directory on a file plugin).
- The explicit HTTP-plugin message above.
- `columns could not be determined for `<schema>`.`<table>` because the
  probe returned no rows; the table may be empty.` — dynamic-schema probe
  returned zero rows.
- Drill's own error text for any other query failure (missing table,
  permissions, etc.), unmodified — Drill's error text does not embed cell
  content, so nothing is redacted from it here.

---

## `list_storage_plugins`

```
list_storage_plugins() -> list[dict]
```

Lists every configured storage plugin, with secrets redacted.

**Parameters:** none. **Requires the REST backend.**

**Returns** a list of plugin config dicts, shape defined by Drill's own
`/storage.json`, e.g.:

```json
[
  {
    "name": "s3",
    "config": {
      "type": "file",
      "connection": "s3a://my-bucket",
      "accessKey": "***REDACTED***",
      "secretKey": "***REDACTED***"
    }
  }
]
```

**Redaction is always on and is not configurable off** — see
[`drill_mcp/redact.py`](../drill_mcp/redact.py). Any dict key matching (case
insensitively, anywhere in the key) `password`, `passwd`, `secret`,
`credential`, `token`, `access[._-]?key`, `private[._-]?key`, `api[._-]?key`,
`session[._-]?key`, `authorization`, `passphrase`, `keytab`, or `principal`
has its value replaced with `"***REDACTED***"`, recursively through nested
dicts, lists, and tuples. This is deliberately broad — a false-positive
redaction is a cosmetic problem, a missed one is a leaked credential — so a
non-secret key that happens to match (e.g. a plugin literally named
`tokenizer`) is redacted too.

Plugins backing a hidden schema (per `hidden_schemas`) are omitted from the
returned list entirely, matched on the plugin's `name`.

**Errors**

- `'storage_plugins' needs a REST connection to Drill; the JDBC backend does
  not expose management endpoints` — JDBC backend.
- Drill's own error text otherwise.
- A non-dict entry in Drill's plugin list is silently skipped rather than
  raising (defensive, in case Drill's REST response is malformed).

---

## `cluster_status`

```
cluster_status() -> dict
```

Reports Drillbit membership and overall cluster status.

**Parameters:** none. **Requires the REST backend.**

**Returns** the merge of Drill's `/cluster.json` and `/status.json`
responses into one dict (`/status.json`'s keys win on any name collision):

```json
{
  "drillbits": [{"address": "10.0.0.5", "userPort": 31010, "state": "ONLINE"}],
  "status": "Running!",
  "version": "1.21.1"
}
```

**Errors**

- `'cluster_status' needs a REST connection to Drill; the JDBC backend does
  not expose management endpoints` — JDBC backend.
- Drill's own error text otherwise.

---

## `list_profiles`

```
list_profiles(limit: int = 20) -> list[dict]
```

Lists recent and currently-running query profiles, newest first.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `limit` | integer | yes, default **`20`** | Caps the number of profiles returned. Combines Drill's `runningQueries` and `finishedQueries` lists (running first) and truncates to `limit`. A negative `limit` is clamped to `0` (returns `[]`), not rejected. |

Note: the default is `20`, not `None` — check the live tool schema if a
client surfaces defaults, since a caller passing no `limit` at all still
gets at most 20 profiles back, not an unbounded list.

**Returns** a list of profile summary dicts, shape defined by Drill's
`/profiles.json`, passed through the same secret redaction as
`list_storage_plugins` (profiles are cluster-wide and can carry other
users' connection strings). Any entry whose query text names a
`hidden_schemas` entry is dropped entirely, the same protection
`list_schemas`/`list_tables` apply — otherwise a hidden schema's name would
leak out as data in another user's query text:

```json
[
  {"queryId": "24680246-...", "state": "RUNNING", "query": "SELECT * FROM ..."},
  {"queryId": "13570246-...", "state": "COMPLETED", "query": "SELECT 1"}
]
```

**Errors**

- `'profiles' needs a REST connection to Drill; the JDBC backend does not
  expose management endpoints` — JDBC backend.
- `limit must be an integer` — `limit` was supplied but not an `int` (a
  `bool` is explicitly rejected too, since `bool` is a subclass of `int` in
  Python and `True`/`False` as a row limit would be a confusing accident).
- Drill's own error text otherwise.

---

## `get_profile`

```
get_profile(query_id: str) -> dict
```

Fetches the full profile for one query id.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `query_id` | string | no | Drill's query UUID, as returned in `run_query`'s `query_id` field (REST backend only — always `null` on JDBC). Validated against `[A-Za-z0-9-]+`. |

**Returns** Drill's full profile JSON for that query — the complete
`/profiles/<query_id>.json` payload (fragments, operator metrics, timing,
etc.), which can be large — passed through the same secret redaction as
`list_storage_plugins`. A full profile embeds Drill's serialized physical
plan, which for JDBC and HTTP storage plugins can carry plugin
configuration, so this is not returned unmodified.

**Errors**

- `'profile' needs a REST connection to Drill; the JDBC backend does not
  expose management endpoints` — JDBC backend.
- `query_id must be a string` — wrong type.
- `invalid query id: '<x>'` — `query_id` contains characters outside
  `[A-Za-z0-9-]`. Rejected before any request is made.
- `profile '<id>' references a hidden schema` — the profile's query text
  names a `hidden_schemas` entry.
- Drill's own error text otherwise (e.g. no profile with that id).

---

## `cancel_query`

```
cancel_query(query_id: str) -> str
```

Cancels a running query by its query id.

**Parameters**

| Name | Type | Optional | Notes |
|---|---|---|---|
| `query_id` | string | no | Same validation as `get_profile`. |

**Returns** Drill's raw response text from `/profiles/cancel/<query_id>`
(a short human-readable string, e.g. `"Cancelled query <id>"`), passed
through unmodified — not parsed as JSON, not restructured.

**Errors**

- `'cancel_query' needs a REST connection to Drill; the JDBC backend does
  not expose management endpoints` — JDBC backend.
- `query_id must be a string` — wrong type.
- `invalid query id: '<x>'` — invalid characters.
- Drill's own error text otherwise (e.g. the query id does not exist or has
  already completed).
