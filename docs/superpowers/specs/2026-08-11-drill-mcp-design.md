# Apache Drill MCP Server — Design

**Date:** 2026-08-11
**Status:** Approved, ready for implementation planning

## Purpose

An MCP server that lets an LLM client explore and query an Apache Drill cluster:
enumerate schemata, run SQL, inspect storage plugins, and read cluster/query
management state. Intended to be donated as the official Drill MCP server, so it
must be conservative by default: a misbehaving model must not be able to mutate
cluster configuration or write data into a store nobody authorized.

## Non-goals

- Storage plugin creation, update, or deletion. These REST endpoints are never
  wired up — there is no flag that enables them.
- `ALTER SYSTEM` / system option mutation. Never exposed.
- Connection pooling, result caching, query result pagination beyond a row cap.

## Architecture

Python package `drill-mcp`, exposing a single MCP server over stdio built on
FastMCP from the official `mcp` SDK.

Two backends sit behind one narrow client interface:

```
DrillClient (protocol)
├── RestClient   httpx against /query.json, /storage, /profiles, /cluster   [default]
└── JdbcClient   jaydebeapi + JPype + drill-jdbc-all.jar                    [opt-in]
```

The protocol is deliberately small — `query`, `schemas`, `tables`, `columns`,
plus REST-only management calls that `JdbcClient` does not implement. Management
tools always route through a REST connection; when the configured backend is
JDBC, the server still opens a REST session for them, or reports the management
tools as unavailable if no REST endpoint is configured.

JDBC lives in an optional extra (`pip install drill-mcp[jdbc]`) so the JVM is
never a hard dependency. Its main reason to exist is Kerberos, which is
materially less painful through the Drill JDBC driver than through Python
SPNEGO. REST + SPNEGO is supported and tried first.

### Module layout

```
drill_mcp/
  __init__.py
  config.py        load + validate configuration
  client_rest.py   RestClient
  client_jdbc.py   JdbcClient (imports guarded; extra not installed → clear error)
  guard.py         SQL policy enforcement
  server.py        FastMCP tool definitions
tests/
  test_config.py
  test_guard.py
  test_client_rest.py
  test_client_jdbc.py
  test_server.py
```

Each module has one job and can be tested without the others. `guard.py` in
particular is pure — string in, decision out, no I/O — so it can be exhaustively
table-tested.

## Tools

| Tool | Arguments | Backend | Notes |
|---|---|---|---|
| `run_query` | `sql`, `max_rows` | either | Passes through `guard.py` first |
| `list_schemas` | — | INFORMATION_SCHEMA | Hidden schemas filtered out |
| `list_tables` | `schema` | INFORMATION_SCHEMA | Hidden schemas filtered out |
| `describe_table` | `schema`, `table` | INFORMATION_SCHEMA.COLUMNS | Errors on hidden schema |
| `list_storage_plugins` | — | REST `/storage` | Secrets redacted |
| `cluster_status` | — | REST `/cluster.json`, `/status` | |
| `list_profiles` | `limit` | REST `/profiles` | |
| `get_profile` | `query_id` | REST `/profiles/{id}.json` | |
| `cancel_query` | `query_id` | REST | |

`max_rows` is capped by config (`max_rows` default 1000) regardless of what the
caller asks for, so a `SELECT *` against a large table cannot flood the context
window.

### Secret redaction

`list_storage_plugins` returns plugin configurations that routinely contain AWS
access keys, JDBC passwords, and OAuth tokens. Before returning, the server
walks the config tree and replaces the value of any key matching a redaction
pattern (`password`, `secret`, `accessKey`, `access_key`, `token`, `credential`,
`privateKey`, case-insensitive) with `"***REDACTED***"`. Redaction is applied
recursively, including inside `credentialsProvider` blocks and nested
`workspaces` entries.

This is a trust boundary: MCP tool output goes to a model and often to a
third-party API. Redaction is not configurable off.

## Write policy

Default deny. Configuration lists the plugins permitted to accept data writes:

```yaml
writable_plugins: []      # e.g. [dfs.tmp]
```

`guard.py` parses each statement with `sqlglot` and applies:

- Exactly one statement per call. Multiple statements are rejected.
- `SELECT`, `SHOW`, `DESCRIBE`, and `WITH ... SELECT` are allowed. The read
  branch sweeps the whole subtree, not just the root node, so a read-rooted
  statement that writes deeper down (`WITH x AS (INSERT ... RETURNING *)
  SELECT ...`, `SELECT ... INTO ...`) is still rejected.
- `EXPLAIN` is allowed, but the guard strips the leading `EXPLAIN` /
  `EXPLAIN PLAN FOR` and re-checks the remainder, so the write allowlist and
  hidden-schema rules apply to the explained statement. Allowing `EXPLAIN` on
  the strength of its leading keyword alone would let `EXPLAIN PLAN FOR CREATE
  TABLE ...` reach Drill without the allowlist ever running.
- `CREATE TABLE AS`, `CREATE VIEW`, `CREATE TEMPORARY TABLE AS`, `DROP TABLE`,
  and `DROP VIEW` are allowed **only** when the target's leading identifier
  (the plugin, or plugin plus workspace) matches an entry in
  `writable_plugins`. Matching is case-insensitive and prefix-aware: an entry of
  `dfs` permits `dfs.tmp.foo`; an entry of `dfs.tmp` does not permit `dfs.raw.foo`.
- Everything else — `INSERT`, `ALTER`, `SET`, `USE`, `REFRESH`, anything
  unrecognized — is rejected.
- A parse failure is a rejection, not a pass-through. This covers tokenizer
  failures (`sqlglot.errors.TokenError`) as well as parse failures — they are
  siblings under `SqlglotError`, not parent and child, and unterminated string
  literals are exactly the input an adversarial caller produces.

`sqlglot` rather than regex, deliberately. A regex guard is defeated by
`-- CREATE TABLE` in a comment or `'DROP TABLE'` inside a string literal, and by
statement stacking. The guard is the only thing standing between a model and the
user's data, so it gets a real parser.

Drill's SQL is Calcite-based; `sqlglot`'s Postgres dialect is the closest fit.
Where a legitimate Drill query fails to parse, the failure is a rejection with a
clear message naming `guard.py` — a false negative that blocks a read is
acceptable; a false positive that permits a write is not.

## Hidden schemas

```yaml
hidden_schemas: []        # e.g. [sys, INFORMATION_SCHEMA]
```

Case-insensitive. Hiding `sys` hides all of `sys.*` (`sys.options`,
`sys.drillbits`, `sys.memory`, …). Default empty, matching stock Drill; hiding
is opt-in.

Enforced at three points, because blocking only one leaks through the others:

1. **Guard.** The same `sqlglot` pass that checks writes walks every table
   reference in the statement and rejects the query if any resolves into a
   hidden schema. This covers subqueries, CTEs, joins, and set operations, not
   just the top-level `FROM`.
2. **Metadata tools.** `list_schemas` and `list_tables` omit hidden entries;
   `describe_table` against a hidden schema returns an error.
3. **`SHOW SCHEMAS` / `SHOW TABLES`.** Drill evaluates these server-side, so the
   server filters the returned rows rather than relying on the guard.

**Deliberate asymmetry:** hiding `INFORMATION_SCHEMA` does not disable the
metadata tools, which query it internally. They keep working and simply omit
hidden schemas from their output. The goal is to stop the model reading the
catalog directly and seeing cluster internals, not to make `list_tables`
useless.

## Authentication

Three modes, selected by config:

- `none` — anonymous cluster (embedded/dev).
- `basic` — Drill's HTTP form login (`/j_security_check`); the resulting session
  cookie is held on the httpx client and reused. On a 401 mid-session the client
  re-authenticates once and retries.
- `kerberos` — SPNEGO via `requests-kerberos`/`httpx-gssapi` for REST; the JDBC
  backend uses the driver's own Kerberos support.

Credentials come from environment variables (`DRILL_USER`, `DRILL_PASSWORD`) or
the config file, never from tool arguments. A model must not be able to pass or
elicit credentials through a tool call.

## Configuration

Resolution order, later overriding earlier: config file → environment variables
→ CLI flags.

```yaml
url: http://localhost:8047        # DRILL_URL
backend: rest                     # rest | jdbc
auth: none                        # none | basic | kerberos
user: null                        # DRILL_USER
password: null                    # DRILL_PASSWORD
max_rows: 1000
timeout_seconds: 60
writable_plugins: []
hidden_schemas: []
jdbc_driver_path: null            # required when backend=jdbc
```

Validation is strict and happens at startup, not at first tool call: unknown
keys are an error, `backend: jdbc` without `jdbc_driver_path` is an error,
`auth: basic` without credentials is an error. A server that starts is a server
that is configured correctly.

## Error handling

Tool errors are returned as MCP tool errors with a short, actionable message —
never a raw traceback, which wastes context and can leak paths or credentials.
Distinct cases:

- Policy rejection (write, hidden schema, parse failure) — states which rule
  fired and, for writes, what `writable_plugins` would need to contain.
- Connection/auth failure — states the URL and auth mode, not the credentials.
- Drill query error — Drill's own error text is passed through, truncated to a
  sane length, since it is what the model needs to fix its SQL.
- Row cap hit — result includes a `truncated: true` marker so the model knows
  it is not seeing everything.

## Testing

Complete unit coverage of every public function. `pytest`, with `respx` faking
the Drill REST endpoints so the entire suite runs with no cluster and no JVM.

- **`test_guard.py`** — the heaviest suite, table-driven. Allowed reads;
  rejected writes with empty `writable_plugins`; permitted writes with matching
  plugin; prefix matching and non-matching; case variants; comment injection
  (`-- CREATE TABLE`); string-literal injection (`SELECT 'DROP TABLE x'`);
  stacked statements; parse failures; hidden schema in `FROM`, in a join, in a
  subquery, in a CTE, in a set operation; unqualified table names.
- **`test_config.py`** — precedence across file/env/CLI, every validation error
  path, defaults.
- **`test_client_rest.py`** — request shape for each endpoint, basic-auth login
  and cookie reuse, 401 re-auth-and-retry, timeout handling, secret redaction
  against a realistic plugin config containing nested credentials.
- **`test_client_jdbc.py`** — against a mocked `jaydebeapi`; also asserts the
  clear error when the `jdbc` extra is not installed.
- **`test_server.py`** — each tool's happy path and its policy-rejection path,
  `max_rows` capping and the `truncated` marker, `SHOW SCHEMAS` row filtering.

An optional integration suite marked `@pytest.mark.integration` runs against a
real Drill in Docker and is skipped by default.

## Deferred

Connection pooling, result caching, streaming large results, storage plugin
CRUD, `ALTER SYSTEM`, OAuth/bearer auth. Add pooling when a single client
connection measurably bottlenecks; add the rest only on a concrete request.
