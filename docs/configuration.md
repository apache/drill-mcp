# Configuration reference

`drill-mcp` is configured from three sources, merged in this order (each
later source overrides keys set by an earlier one):

1. **Config file** (`--config path/to/drill.yaml`), a YAML mapping.
2. **Environment variables** (`DRILL_*`).
3. **CLI flags.**

There is no partial precedence per key: for any given key, whichever of the
three sources set it last (file, then environment, then CLI) wins outright.
A stale exported `DRILL_PASSWORD`, for example, silently overrides a
`password:` set in the config file — `unset` it if the file is meant to be
authoritative.

`user`/`password` can only come from the config file or from
`DRILL_USER`/`DRILL_PASSWORD`. There is no `--user`/`--password` CLI flag,
and no tool accepts a credential as an argument — credentials never appear
in a process's argv, where they would be visible to anything that can list
processes.

An example file with every key present is at
[`drill.example.yaml`](../drill.example.yaml).

## Unknown keys

The config file is validated strictly (Pydantic `extra="forbid"`): a key in
the YAML file that is not one of the fields below raises a `ConfigError` and
the server refuses to start. This also catches typos (e.g. `uurl:` instead
of `url:`) that would otherwise silently be ignored. Validation happens at
startup, not at first tool call — a server that starts is a server that is
configured correctly.

Numeric fields (`max_rows`, `timeout_seconds`) may be given as YAML strings
or environment-variable strings; they are coerced to `int` before
validation, and a value that cannot be parsed as an integer is a
`ConfigError`.

## Keys

| Key | Type | Default | Env var | CLI flag |
|---|---|---|---|---|
| `url` | string | `http://localhost:8047` | `DRILL_URL` | `--url` |
| `backend` | `rest` \| `jdbc` | `rest` | `DRILL_BACKEND` | `--backend` |
| `auth` | `none` \| `basic` \| `kerberos` | `none` | `DRILL_AUTH` | `--auth` |
| `user` | string or null | `null` | `DRILL_USER` | *(none)* |
| `password` | string or null | `null` | `DRILL_PASSWORD` | *(none)* |
| `max_rows` | integer > 0 | `1000` | `DRILL_MAX_ROWS` | `--max-rows` |
| `timeout_seconds` | integer > 0 | `60` | `DRILL_TIMEOUT_SECONDS` | *(none)* |
| `writable_plugins` | list of strings | `[]` | *(none)* | `--writable-plugin` (repeatable) |
| `hidden_schemas` | list of strings | `[]` | *(none)* | `--hidden-schema` (repeatable) |
| `jdbc_driver_path` | string or null | `null` | `DRILL_JDBC_DRIVER_PATH` | *(none)* |

`writable_plugins` and `hidden_schemas` have no environment-variable form —
only the config file or the repeatable `--writable-plugin` / `--hidden-schema`
CLI flags can set them. Each `--writable-plugin PLUGIN` or
`--hidden-schema SCHEMA` flag appends one entry; a CLI-supplied list replaces
the file's list entirely (there is no merging of file and CLI entries for
these two keys).

### `--timeout-seconds`

There is no `--timeout-seconds` CLI flag, only the config file and
`DRILL_TIMEOUT_SECONDS`. `timeout_seconds` bounds the HTTP client's
connect/read timeout for the REST backend (`httpx.Client(timeout=...)`); it
is not consulted by the JDBC backend at all.

## Cross-field validation

Beyond per-field types, `Config` enforces two consistency rules after all
sources are merged:

- `auth: basic` requires both `user` and `password` to be set; otherwise
  `ConfigError`.
- `backend: jdbc` requires `jdbc_driver_path` to be set; otherwise
  `ConfigError`.

## `writable_plugins` and `hidden_schemas` matching

Both are lists of dotted plugin/schema prefixes (e.g. `dfs.tmp`, `sys`).
Matching is case-insensitive and component-wise: an entry `dfs` matches
`dfs.tmp` and `dfs.tmp.nested`, but not `dfsx.tmp` (matching is on whole
dotted components, not a raw string prefix). See
[`docs/tools.md`](tools.md) for how each list is enforced and its
surprising edge cases (in particular, `hidden_schemas` filtering the rows of
every `SHOW` command, not only `SHOW SCHEMAS`).
