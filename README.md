# drill-mcp

An MCP server for [Apache Drill](https://drill.apache.org/). Lets an MCP client
enumerate schemata, run SQL, and inspect storage plugin and cluster state.

## Install

```bash
pip install drill-mcp             # REST backend
pip install drill-mcp[jdbc]       # adds the JDBC backend (needs a JVM)
pip install drill-mcp[kerberos]   # adds SPNEGO for the REST backend
```

## Run

```bash
drill-mcp --url http://localhost:8047
drill-mcp --config drill.yaml
```

Register it with an MCP client:

```json
{
  "mcpServers": {
    "drill": {
      "command": "drill-mcp",
      "args": ["--config", "/etc/drill-mcp/drill.yaml"]
    }
  }
}
```

`drill-mcp --help` lists every flag; `drill.example.yaml` documents every
config key. CLI flags override the config file, which overrides the
`DRILL_*` environment variables, which override the built-in defaults.
Credentials (`user`/`password`) are read from the config file or from
`DRILL_USER`/`DRILL_PASSWORD` only -- there is no `--user`/`--password` flag,
and no tool accepts a credential as an argument.

## Tools

| Tool | Description |
|---|---|
| `run_query` | Run one SQL statement |
| `list_schemas` | List visible schemas |
| `list_tables` | List tables in a schema |
| `describe_table` | Column names and types |
| `list_storage_plugins` | Plugin configs, secrets redacted |
| `cluster_status` | Drillbit membership and status |
| `list_profiles` | Recent and running queries |
| `get_profile` | Full profile for one query id |
| `cancel_query` | Cancel a running query |

The management tools (`list_storage_plugins`, `cluster_status`,
`list_profiles`, `get_profile`, `cancel_query`) need Drill's REST management
endpoints; they raise a clear `ToolError` when the JDBC backend is in use,
rather than failing silently.

## Safety model

- **Writes are denied by default.** `CREATE TABLE AS`, `CREATE VIEW`, and
  `DROP` are permitted only into plugins listed in `writable_plugins`.
  `INSERT`, `ALTER`, and `USE` are always rejected, no matter what
  `writable_plugins` contains.
- **`ALTER SYSTEM` and storage plugin create/update/delete are not
  implemented at all.** There is no flag, config key, or code path that
  turns them on -- there is nothing for such a tool to call.
- **`EXPLAIN` recurses.** The guard strips a leading `EXPLAIN` or
  `EXPLAIN PLAN FOR` and re-checks the remaining statement against the same
  allowlist and hidden-schema rules, so `EXPLAIN` cannot be used to peek at
  or execute a statement that would otherwise be rejected. Recursion is
  bounded so a chain of nested `EXPLAIN EXPLAIN ...` cannot exhaust the
  stack.
- **Every statement is checked with a real SQL parser** (sqlglot's Drill
  dialect), not a regex, so a write hidden in a comment, a string literal,
  or a stacked statement does not slip through.
- **Secrets are always redacted** from storage plugin output. This is not
  configurable off.

## Hidden schemas

`hidden_schemas` removes schemas (and their children -- hiding `sys` also
hides `sys.mem`, `sys.options`, etc.) from `list_schemas` and
`list_storage_plugins`, and `list_tables`/`describe_table` refuse to operate
on a hidden schema at all.

`SHOW` commands (`SHOW SCHEMAS`, `SHOW DATABASES`, `SHOW TABLES`, `SHOW
FILES`, ...) are evaluated server-side by Drill, so the guard cannot filter
them by rewriting the query; instead, `run_query` filters the *first column
of every row* of *every* `SHOW` command's result against `hidden_schemas`.

This is broader than filtering just `SHOW SCHEMAS`/`SHOW DATABASES`, and
that is deliberate. Drill has no single, reliably-recognizable spelling for
"a `SHOW` that lists schemas" -- three narrower approaches (a regex over the
raw SQL text, exact matching against sqlglot's parsed literal, a
comment-stripping regex over that literal) were each defeated by some
spelling (a leading/trailing comment, `SHOW SCHEMAS LIKE '...'`, a nested or
unbalanced comment token) and leaked hidden schema names through. Filtering
every `SHOW` result's first column closes all of those gaps at once, at the
cost of also filtering `SHOW TABLES`/`SHOW FILES` rows: a table or file
whose name happens to match a hidden-schema prefix is hidden too, even
though it is not itself a schema. A false positive here (a real table
briefly missing from a listing) is an acceptable trade for never leaking a
schema name the operator asked to hide.

**Hiding `INFORMATION_SCHEMA` does not break the metadata tools.**
`list_schemas`, `list_tables`, and `describe_table` query
`INFORMATION_SCHEMA` internally regardless of what is hidden; they simply
omit hidden schemas from what they return to the caller.

## Column discovery

`describe_table`'s strategy depends on how the underlying storage plugin
registers its schema:

- For plugins with a schema registered ahead of time (most JDBC-style and
  relational-style plugins), `describe_table` uses Drill's `DESCRIBE`, which
  is metadata-only and never reads user data.
- For plugins whose schema is only known at read time (`file`, `mongo`,
  `splunk`), `DESCRIBE` cannot answer, so `describe_table` probes with
  `SELECT ... LIMIT 1` against the target instead. It returns **only column
  names and types** -- the sampled row itself is never included in the
  result.
- **HTTP plugins cannot report columns until a query has been run** against
  the endpoint; Drill has no schema for an HTTP source ahead of a real
  request. `describe_table` says this explicitly in its error rather than
  returning an empty column list.

`list_tables` uses `SHOW FILES` instead of `INFORMATION_SCHEMA.TABLES` for
file plugins, since file-based storage plugins do not register their
contents in `INFORMATION_SCHEMA`.

## Backends

- **REST** (default): talks to a Drillbit's HTTP endpoints over `httpx`.
  Works out of the box, no JVM required.
- **JDBC** (`backend: jdbc`, the `[jdbc]` extra): uses `jaydebeapi`/`JPype1`
  against Drill's JDBC driver. Exists mainly for Kerberos environments where
  the REST endpoint's SPNEGO support is impractical. Needs a JVM and
  `jdbc_driver_path` pointing at `drill-jdbc-all.jar`. The management tools
  are unavailable on this backend, since Drill's management API is
  REST-only.

Wire-level behavior (identifier quoting, `INFORMATION_SCHEMA` queries,
per-plugin-type column discovery) follows
[`sqlalchemy-drill`](https://github.com/JohnOmernik/sqlalchemy-drill), the
most complete and maintained reference for talking to Drill from Python.
`PyDrill` was evaluated and not adopted: it has no form-based login, no
Kerberos support, and its last release was in 2018.

See `drill.example.yaml` for the full configuration reference.

## Development

```bash
pip install -e ".[dev]"
pytest                       # unit tests, no cluster or JVM needed
pytest -m integration        # requires a live Drill at DRILL_URL
```
