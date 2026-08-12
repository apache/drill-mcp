# drill-mcp

An [MCP](https://modelcontextprotocol.io/) server for [Apache Drill](https://drill.apache.org/).
It lets an MCP client run read-only (and narrowly, explicitly allow-listed
write) SQL against a Drill cluster, and inspect schemas, storage plugins,
and cluster/query state. It does not implement Drill administration
(`ALTER SYSTEM`, storage-plugin management) — see "Safety model" below.

## Install

```bash
pip install drill-mcp             # REST backend
pip install drill-mcp[jdbc]       # adds the JDBC backend (needs a JVM)
pip install drill-mcp[kerberos]   # adds SPNEGO auth for the REST backend
```

The base install has no JVM dependency: the default REST backend talks to
Drill over plain HTTP via `httpx`. The `jdbc` extra pulls in
`jaydebeapi`/`JPype1` and is only needed if you select `backend: jdbc`
(see "Backends" below).

## Quickstart

```bash
drill-mcp --url http://localhost:8047
# or
drill-mcp --config /etc/drill-mcp/drill.yaml
```

`drill-mcp --help` lists every CLI flag.

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

## Configuration

Configuration is merged from three sources, each overriding the last:
**config file** → **`DRILL_*` environment variables** → **CLI flags**.
Because the environment wins over the file, a stale exported
`DRILL_PASSWORD` silently overrides a `password:` set in the config file —
`unset` it if the file is meant to be authoritative.

There is no `--user`/`--password` CLI flag and no tool accepts a credential
as an argument; `user`/`password` can only be set via the config file or
`DRILL_USER`/`DRILL_PASSWORD`.

Every config key, its default, its environment variable, and its CLI flag
are documented in [`docs/configuration.md`](docs/configuration.md).
[`drill.example.yaml`](drill.example.yaml) is a complete example file with
every key present.

## Tools

| Tool | Description |
|---|---|
| `run_query` | Run one SQL statement |
| `list_schemas` | List visible schemas |
| `list_tables` | List tables in a schema |
| `describe_table` | Column names, types, and nullability where the plugin reports it |
| `list_storage_plugins` | Plugin configs, secrets redacted |
| `cluster_status` | Drillbit membership and status |
| `list_profiles` | Recent and running queries |
| `get_profile` | Full profile for one query id |
| `cancel_query` | Cancel a running query |

`list_storage_plugins`, `cluster_status`, `list_profiles`, `get_profile`,
and `cancel_query` are **management tools**: they require the REST backend
and raise a clear `ToolError` on the JDBC backend rather than failing
silently or returning empty data.

Full parameters, return shapes, errors, and per-tool surprises are in
[`docs/tools.md`](docs/tools.md).

## Safety model

- **Writes are denied by default.** `CREATE TABLE AS`, `CREATE VIEW`,
  `DROP TABLE`, and `DROP VIEW` are permitted only into plugins listed in
  `writable_plugins`. `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `ALTER`,
  `USE`, and `REFRESH` are always rejected, no matter what
  `writable_plugins` contains.
- **`ALTER SYSTEM` and storage-plugin create/update/delete are not
  implemented at all.** There is no flag, config key, or code path that
  turns them on — there is nothing for such a tool to call.
- **Exactly one statement per call**, checked with a real SQL parser
  (sqlglot's Drill dialect), not a regex, so a write hidden in a comment, a
  string literal, or a stacked statement does not slip through. Anything
  that fails to parse — including a tokenizer failure — is rejected.
- **`EXPLAIN` recurses.** The guard strips a leading `EXPLAIN` or `EXPLAIN
  PLAN FOR` and re-checks the remaining statement against the same
  allowlist and hidden-schema rules, with bounded recursion depth.
- **`hidden_schemas` filters more than schema listings.** Beyond refusing
  queries against a hidden schema, it filters the result rows of *every*
  `SHOW` command (not only `SHOW SCHEMAS`), because Drill's `SHOW` grammar
  gives sqlglot no reliable way to identify which spelling lists schemas.
  This is a deliberate fail-closed trade: a table or file whose name
  happens to match a hidden-schema prefix is incidentally hidden too. See
  [`docs/tools.md`](docs/tools.md#run_query) for the full explanation.
  Hiding `INFORMATION_SCHEMA` does not break the metadata tools, which
  query it internally regardless and simply omit hidden entries from their
  output.
- **Secrets are always redacted** from `list_storage_plugins` output. This
  is not configurable off.
- **Results are capped** by `max_rows`; a caller may lower the cap for a
  single call but never raise it above the configured limit. A truncated
  result is marked `"truncated": true`.

## Backends

- **REST** (default, `backend: rest`): talks to a Drillbit's HTTP endpoints
  over `httpx`. Works out of the box, no JVM required.
- **JDBC** (`backend: jdbc`, needs the `jdbc` extra): uses
  `jaydebeapi`/`JPype1` against Drill's JDBC driver. It exists mainly
  because Kerberos is materially less painful through the Drill JDBC
  driver than through Python SPNEGO. It needs a JVM and `jdbc_driver_path`
  pointing at `drill-jdbc-all.jar`. Management tools are unavailable on
  this backend, since Drill's management API is REST-only, and `run_query`
  never returns a `query_id` on this backend.

Wire-level behavior — identifier quoting, `INFORMATION_SCHEMA` queries, and
the per-plugin-type column-discovery strategy in `describe_table` — follows
[`sqlalchemy-drill`](https://github.com/JohnOmernik/sqlalchemy-drill), the
most complete and maintained reference for talking to Drill from Python.
`PyDrill` was evaluated and not adopted: it has no form-based login, no
Kerberos support, and its last release was in 2018.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite needs no live Drill cluster and no JVM: Drill's wire
protocol is mocked at the transport boundary, so `pytest` runs anywhere
Python does.

## Credits and license

Wire-level behavior follows [`sqlalchemy-drill`](https://github.com/JohnOmernik/sqlalchemy-drill).

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
