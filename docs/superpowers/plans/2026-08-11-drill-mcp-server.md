# Apache Drill MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an MCP server that lets an LLM client explore and query an Apache Drill cluster safely — enumerate schemata, run SQL, read storage plugin and cluster state — with writes denied by default.

**Architecture:** A Python package exposing one MCP server over stdio via FastMCP. A narrow `DrillClient` protocol has two implementations: `RestClient` (httpx against Drill's HTTP endpoints, the default) and `JdbcClient` (optional extra, exists mainly for Kerberos). All user-supplied SQL passes through a pure policy module, `guard.py`, before reaching any client. Tool bodies live on a plain `DrillTools` class so they can be unit-tested without standing up an MCP session.

**Tech Stack:** Python 3.11+, `mcp` (FastMCP), `httpx`, `sqlglot`, `pydantic`, `PyYAML`. Optional: `jaydebeapi`/`JPype1`. Dev: `pytest`, `respx`, `pytest-cov`.

**Spec:** `docs/superpowers/specs/2026-08-11-drill-mcp-design.md`

## Global Constraints

- Python 3.11 or newer. Use `X | None` union syntax, not `Optional[X]`.
- Storage plugin create/update/delete and `ALTER SYSTEM` are **never** implemented. There is no flag that enables them. Do not add the endpoints.
- Secret redaction is not configurable off.
- Credentials are read from config or environment only. No tool may accept a credential as an argument.
- Every public function gets unit tests. The full suite must run with no Drill cluster and no JVM.
- `guard.py` is pure — no I/O, no config loading, no network. It takes a string and a policy, and returns or raises.
- A parse failure in the guard is a **rejection**, never a pass-through.
- Commit after every task. Conventional-commit prefixes (`feat:`, `test:`, `chore:`).

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Packaging, dependencies, the `jdbc` extra, pytest config |
| `drill_mcp/__init__.py` | Version constant only |
| `drill_mcp/config.py` | `Config` model, file/env/CLI precedence, startup validation |
| `drill_mcp/guard.py` | `Policy`, `PolicyError`, `check()` — pure SQL policy |
| `drill_mcp/redact.py` | Recursive secret redaction |
| `drill_mcp/client_rest.py` | `RestClient` — auth, query, metadata, management |
| `drill_mcp/client_jdbc.py` | `JdbcClient` — query + metadata only |
| `drill_mcp/server.py` | `DrillTools` methods, `build_server`, `main()` entry point |
| `tests/test_*.py` | One test module per source module |

Task order builds inward-out: config and the pure guard first (no dependencies, heaviest tests), then clients, then the tool layer that composes them.

---

### Task 1: Project scaffolding and configuration

**Files:**
- Create: `pyproject.toml`, `drill_mcp/__init__.py`, `drill_mcp/config.py`, `.gitignore`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `drill_mcp.config.Config` — pydantic model with fields `url: str`, `backend: Literal["rest","jdbc"]`, `auth: Literal["none","basic","kerberos"]`, `user: str | None`, `password: str | None`, `max_rows: int`, `timeout_seconds: int`, `writable_plugins: list[str]`, `hidden_schemas: list[str]`, `jdbc_driver_path: str | None`
  - `drill_mcp.config.load_config(path: str | None = None, env: Mapping[str, str] | None = None, overrides: dict | None = None) -> Config`
  - `drill_mcp.config.ConfigError` — raised on any validation failure

- [ ] **Step 1: Create the package skeleton**

`pyproject.toml`:

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "drill-mcp"
version = "0.1.0"
description = "MCP server for Apache Drill"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "Apache-2.0" }
dependencies = [
    "mcp>=1.2.0",
    "httpx>=0.27",
    "sqlglot>=25.0",
    "pydantic>=2.6",
    "PyYAML>=6.0",
]

[project.optional-dependencies]
jdbc = ["jaydebeapi>=1.2.3", "JPype1>=1.5"]
kerberos = ["httpx-gssapi>=0.3"]
dev = ["pytest>=8.0", "respx>=0.21", "pytest-cov>=5.0"]

[project.scripts]
drill-mcp = "drill_mcp.server:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: requires a live Drill cluster (deselected by default)"]
addopts = "-m 'not integration'"
```

`drill_mcp/__init__.py`:

```python
__version__ = "0.1.0"
```

`.gitignore`:

```
__pycache__/
*.egg-info/
.pytest_cache/
.coverage
dist/
build/
.venv/
```

- [ ] **Step 2: Write the failing config tests**

`tests/test_config.py`:

```python
import pytest

from drill_mcp.config import Config, ConfigError, load_config


def test_defaults_are_conservative():
    cfg = load_config()
    assert cfg.url == "http://localhost:8047"
    assert cfg.backend == "rest"
    assert cfg.auth == "none"
    assert cfg.max_rows == 1000
    assert cfg.timeout_seconds == 60
    assert cfg.writable_plugins == []
    assert cfg.hidden_schemas == []


def test_loads_from_yaml_file(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("url: http://drill:8047\nmax_rows: 50\nwritable_plugins: [dfs.tmp]\n")
    cfg = load_config(str(path))
    assert cfg.url == "http://drill:8047"
    assert cfg.max_rows == 50
    assert cfg.writable_plugins == ["dfs.tmp"]


def test_env_overrides_file(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("url: http://from-file:8047\n")
    cfg = load_config(str(path), env={"DRILL_URL": "http://from-env:8047"})
    assert cfg.url == "http://from-env:8047"


def test_cli_overrides_env(tmp_path):
    cfg = load_config(
        env={"DRILL_URL": "http://from-env:8047"},
        overrides={"url": "http://from-cli:8047"},
    )
    assert cfg.url == "http://from-cli:8047"


def test_credentials_read_from_env():
    cfg = load_config(env={"DRILL_USER": "alice", "DRILL_PASSWORD": "s3cret", "DRILL_AUTH": "basic"})
    assert cfg.user == "alice"
    assert cfg.password == "s3cret"


def test_unknown_key_is_an_error(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("uurl: http://typo:8047\n")
    with pytest.raises(ConfigError, match="uurl"):
        load_config(str(path))


def test_basic_auth_requires_credentials():
    with pytest.raises(ConfigError, match="user"):
        load_config(overrides={"auth": "basic"})


def test_jdbc_backend_requires_driver_path():
    with pytest.raises(ConfigError, match="jdbc_driver_path"):
        load_config(overrides={"backend": "jdbc"})


def test_invalid_backend_is_an_error():
    with pytest.raises(ConfigError):
        load_config(overrides={"backend": "carrier-pigeon"})


def test_max_rows_must_be_positive():
    with pytest.raises(ConfigError):
        load_config(overrides={"max_rows": 0})


def test_missing_config_file_is_an_error():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/drill.yaml")


def test_config_is_immutable():
    cfg = load_config()
    with pytest.raises(Exception):
        cfg.url = "http://elsewhere:8047"
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'drill_mcp.config'`

- [ ] **Step 4: Implement `drill_mcp/config.py`**

```python
"""Configuration loading and validation.

Precedence, later overriding earlier: config file, environment, CLI overrides.
Validation happens at startup, not at first tool call — a server that starts is
a server that is configured correctly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or internally inconsistent."""


_ENV_MAP = {
    "DRILL_URL": "url",
    "DRILL_BACKEND": "backend",
    "DRILL_AUTH": "auth",
    "DRILL_USER": "user",
    "DRILL_PASSWORD": "password",
    "DRILL_MAX_ROWS": "max_rows",
    "DRILL_TIMEOUT_SECONDS": "timeout_seconds",
    "DRILL_JDBC_DRIVER_PATH": "jdbc_driver_path",
}

_INT_FIELDS = {"max_rows", "timeout_seconds"}


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = "http://localhost:8047"
    backend: Literal["rest", "jdbc"] = "rest"
    auth: Literal["none", "basic", "kerberos"] = "none"
    user: str | None = None
    password: str | None = None
    max_rows: int = Field(default=1000, gt=0)
    timeout_seconds: int = Field(default=60, gt=0)
    writable_plugins: list[str] = Field(default_factory=list)
    hidden_schemas: list[str] = Field(default_factory=list)
    jdbc_driver_path: str | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "Config":
        if self.auth == "basic" and not (self.user and self.password):
            raise ValueError("auth: basic requires both user and password")
        if self.backend == "jdbc" and not self.jdbc_driver_path:
            raise ValueError("backend: jdbc requires jdbc_driver_path")
        return self


def load_config(
    path: str | None = None,
    env: Mapping[str, str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    env = os.environ if env is None else env
    values: dict[str, Any] = {}

    if path is not None:
        file_path = Path(path)
        if not file_path.is_file():
            raise ConfigError(f"config file not found: {path}")
        try:
            loaded = yaml.safe_load(file_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"config file is not valid YAML: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError("config file must contain a YAML mapping at the top level")
        values.update(loaded)

    for env_key, field in _ENV_MAP.items():
        if env_key in env:
            values[field] = env[env_key]

    values.update(overrides or {})

    for field in _INT_FIELDS:
        if isinstance(values.get(field), str):
            try:
                values[field] = int(values[field])
            except ValueError as exc:
                raise ConfigError(f"{field} must be an integer") from exc

    try:
        return Config(**values)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_config.py -v`
Expected: PASS, 12 tests

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore drill_mcp/ tests/
git commit -m "feat: package skeleton and configuration loading"
```

---

### Task 2: SQL guard — statement classification and write policy

**Files:**
- Create: `drill_mcp/guard.py`
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: nothing (`guard.py` is pure and standalone)
- Produces:
  - `drill_mcp.guard.Policy` — frozen dataclass, `writable_plugins: tuple[str, ...] = ()`, `hidden_schemas: tuple[str, ...] = ()`, plus classmethod `from_config(cfg) -> Policy`
  - `drill_mcp.guard.PolicyError(Exception)`
  - `drill_mcp.guard.check(sql: str, policy: Policy) -> None` — returns `None` if permitted, raises `PolicyError` otherwise
  - `drill_mcp.guard.matches_prefix(qualified: str, entries: Iterable[str]) -> bool`

**Background for the implementer:** Drill's SQL is Apache Calcite–based, and `sqlglot` ships a native `Drill` dialect — parse with `read="drill"`. Do not substitute a near neighbour: under the Postgres dialect `sqlglot` raises `ParseError` on backtick-quoted identifiers, and because the guard rejects whatever it cannot parse, that silently turns `SELECT * FROM dfs.`/path/file.csv`` and `SELECT * FROM INFORMATION_SCHEMA.`TABLES`` into policy rejections. `sqlglot.parse()` returns a *list* of statements, which is how statement-stacking is detected. Constructs sqlglot does not recognize become `exp.Command`, a catch-all node holding the leading keyword and the raw remainder — so `exp.Command` must never be blanket-allowed.

- [ ] **Step 1: Write a characterization test for sqlglot's parse tree**

This test documents what sqlglot actually does, so the rest of the module can rely on it. Run it first and **fix the assertions to match observed reality** if your `sqlglot` version differs — then build the guard against the corrected facts.

`tests/test_guard.py` (first block):

```python
import pytest
import sqlglot
from sqlglot import exp

from drill_mcp.guard import Policy, PolicyError, check, matches_prefix


class TestSqlglotAssumptions:
    """Characterization tests: what the guard relies on sqlglot doing."""

    def test_parse_returns_one_statement_per_semicolon(self):
        assert len(sqlglot.parse("SELECT 1; SELECT 2", read="drill")) == 2

    def test_select_parses_to_select(self):
        stmt = sqlglot.parse_one("SELECT * FROM dfs.tmp.foo", read="drill")
        assert isinstance(stmt, exp.Select)

    def test_table_exposes_catalog_db_name(self):
        table = sqlglot.parse_one("SELECT * FROM dfs.tmp.foo", read="drill").find(exp.Table)
        assert table.catalog == "dfs"
        assert table.db == "tmp"
        assert table.name == "foo"

    def test_two_part_name_populates_db_not_catalog(self):
        table = sqlglot.parse_one("SELECT * FROM sys.options", read="drill").find(exp.Table)
        assert table.catalog == ""
        assert table.db == "sys"
        assert table.name == "options"

    def test_comments_are_stripped_by_the_tokenizer(self):
        stmt = sqlglot.parse_one("-- CREATE TABLE evil\nSELECT 1", read="drill")
        assert isinstance(stmt, exp.Select)

    def test_ctas_target_is_reachable_from_this(self):
        stmt = sqlglot.parse_one(
            "CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.raw.src", read="drill"
        )
        assert isinstance(stmt, exp.Create)
        target = stmt.this.this if isinstance(stmt.this, exp.Schema) else stmt.this
        assert isinstance(target, exp.Table)
        assert target.catalog == "dfs"
        assert target.db == "tmp"
```

- [ ] **Step 2: Run the characterization test**

Run: `pytest tests/test_guard.py::TestSqlglotAssumptions -v`
Expected: FAIL on the import line — `ModuleNotFoundError: No module named 'drill_mcp.guard'`.

Temporarily comment out the `from drill_mcp.guard import ...` line and re-run to confirm all six assumptions hold against your installed `sqlglot`. Correct any assertion that does not match, then restore the import.

- [ ] **Step 3: Write the failing write-policy tests**

Append to `tests/test_guard.py`:

```python
OPEN = Policy(writable_plugins=("dfs.tmp",))
CLOSED = Policy()


class TestReadsAreAllowed:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1",
            "SELECT * FROM dfs.tmp.foo",
            "SELECT a, b FROM dfs.tmp.foo WHERE a > 1 ORDER BY b",
            "WITH x AS (SELECT * FROM dfs.tmp.foo) SELECT * FROM x",
            "SELECT * FROM dfs.tmp.a UNION SELECT * FROM dfs.tmp.b",
            "SELECT * FROM dfs.tmp.a JOIN dfs.tmp.b ON a.id = b.id",
            "SHOW SCHEMAS",
            "SHOW TABLES",
            "DESCRIBE dfs.tmp.foo",
        ],
    )
    def test_permitted(self, sql):
        check(sql, CLOSED)  # does not raise


class TestWritesAreDeniedByDefault:
    @pytest.mark.parametrize(
        "sql",
        [
            "CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.tmp.src",
            "CREATE VIEW dfs.tmp.v AS SELECT 1",
            "DROP TABLE dfs.tmp.foo",
            "DROP VIEW dfs.tmp.v",
            "INSERT INTO dfs.tmp.foo VALUES (1)",
            "ALTER SYSTEM SET `planner.width.max_per_node` = 4",
            "ALTER SESSION SET `store.format` = 'json'",
            "USE dfs.tmp",
            "REFRESH TABLE METADATA dfs.tmp.foo",
        ],
    )
    def test_rejected_with_no_writable_plugins(self, sql):
        with pytest.raises(PolicyError):
            check(sql, CLOSED)


class TestWritesWithAnAllowlist:
    def test_ctas_into_allowed_plugin_permitted(self):
        check("CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.raw.src", OPEN)

    def test_create_view_into_allowed_plugin_permitted(self):
        check("CREATE VIEW dfs.tmp.v AS SELECT 1", OPEN)

    def test_drop_in_allowed_plugin_permitted(self):
        check("DROP TABLE dfs.tmp.old", OPEN)

    def test_ctas_into_other_plugin_rejected(self):
        with pytest.raises(PolicyError, match="writable_plugins"):
            check("CREATE TABLE s3.bucket.out AS SELECT 1", OPEN)

    def test_sibling_workspace_rejected(self):
        with pytest.raises(PolicyError):
            check("CREATE TABLE dfs.raw.out AS SELECT 1", OPEN)

    def test_plugin_level_entry_permits_any_workspace(self):
        check("CREATE TABLE dfs.raw.out AS SELECT 1", Policy(writable_plugins=("dfs",)))

    def test_matching_is_case_insensitive(self):
        check("CREATE TABLE DFS.TMP.OUT AS SELECT 1", OPEN)

    def test_insert_still_rejected_even_when_plugin_writable(self):
        with pytest.raises(PolicyError):
            check("INSERT INTO dfs.tmp.foo VALUES (1)", OPEN)

    def test_unqualified_target_rejected(self):
        with pytest.raises(PolicyError):
            check("CREATE TABLE bare AS SELECT 1", OPEN)


class TestInjectionAttempts:
    def test_write_hidden_in_a_comment_is_not_a_write(self):
        check("-- CREATE TABLE dfs.tmp.x AS SELECT 1\nSELECT 1", CLOSED)

    def test_write_inside_a_string_literal_is_not_a_write(self):
        check("SELECT 'DROP TABLE dfs.tmp.foo' AS note", CLOSED)

    def test_stacked_statements_rejected(self):
        with pytest.raises(PolicyError, match="one statement"):
            check("SELECT 1; DROP TABLE dfs.tmp.foo", CLOSED)

    def test_stacked_statements_rejected_even_when_both_are_reads(self):
        with pytest.raises(PolicyError, match="one statement"):
            check("SELECT 1; SELECT 2", CLOSED)

    def test_trailing_semicolon_is_fine(self):
        check("SELECT 1;", CLOSED)

    def test_empty_sql_rejected(self):
        with pytest.raises(PolicyError):
            check("   ", CLOSED)

    def test_unparseable_sql_rejected(self):
        with pytest.raises(PolicyError, match="parse"):
            check("SELECT FROM WHERE ((", CLOSED)


class TestMatchesPrefix:
    def test_exact_match(self):
        assert matches_prefix("dfs.tmp", ["dfs.tmp"])

    def test_parent_entry_matches_child(self):
        assert matches_prefix("dfs.tmp", ["dfs"])

    def test_child_entry_does_not_match_parent(self):
        assert not matches_prefix("dfs", ["dfs.tmp"])

    def test_sibling_does_not_match(self):
        assert not matches_prefix("dfs.raw", ["dfs.tmp"])

    def test_case_insensitive(self):
        assert matches_prefix("DFS.TMP", ["dfs.tmp"])

    def test_no_partial_component_match(self):
        assert not matches_prefix("dfsx.tmp", ["dfs"])

    def test_empty_entries_never_match(self):
        assert not matches_prefix("dfs.tmp", [])
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `pytest tests/test_guard.py -v`
Expected: FAIL — `ImportError: cannot import name 'Policy' from 'drill_mcp.guard'`

- [ ] **Step 5: Implement `drill_mcp/guard.py`**

```python
"""SQL policy enforcement. Pure: string in, decision out, no I/O.

Deny by default. Reads are permitted; a write is permitted only when its target
resolves into a plugin the operator explicitly listed in `writable_plugins`.

A real parser rather than a regex, deliberately: a regex guard is defeated by
`-- CREATE TABLE` in a comment, by `'DROP TABLE'` inside a string literal, and
by statement stacking. This module is the only thing standing between a model
and the user's data.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

import sqlglot
from sqlglot import exp

DIALECT = "drill"  # sqlglot ships a native Drill dialect — do not substitute a near neighbour

# Commands sqlglot does not model as expressions, but which cannot write.
_SAFE_COMMANDS = {"SHOW", "DESCRIBE", "DESC", "EXPLAIN"}

_READ_TYPES = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery, exp.Describe)


class PolicyError(Exception):
    """Raised when a statement is not permitted. The message is shown to the caller."""


@dataclass(frozen=True)
class Policy:
    writable_plugins: tuple[str, ...] = ()
    hidden_schemas: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, cfg) -> "Policy":
        return cls(
            writable_plugins=tuple(cfg.writable_plugins),
            hidden_schemas=tuple(cfg.hidden_schemas),
        )


def matches_prefix(qualified: str, entries: Iterable[str]) -> bool:
    """True if any entry is a dotted-component prefix of `qualified`.

    Component-wise so that `dfs` matches `dfs.tmp` but not `dfsx.tmp`.
    """
    parts = [p.lower() for p in qualified.split(".") if p]
    if not parts:
        return False
    for entry in entries:
        entry_parts = [p.lower() for p in entry.split(".") if p]
        if entry_parts and parts[: len(entry_parts)] == entry_parts:
            return True
    return False


def check(sql: str, policy: Policy) -> None:
    """Return None if `sql` is permitted under `policy`; raise PolicyError otherwise."""
    if not sql or not sql.strip():
        raise PolicyError("empty SQL statement")

    try:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except sqlglot.ParseError as exc:
        raise PolicyError(
            f"could not parse SQL, so it cannot be checked against policy and is rejected: {exc}"
        ) from exc

    if len(statements) != 1:
        raise PolicyError(
            f"exactly one statement per call is permitted, got {len(statements)}"
        )

    statement = statements[0]
    _check_hidden(statement, policy)
    _check_write(statement, policy)


def _check_write(statement: exp.Expression, policy: Policy) -> None:
    if isinstance(statement, _READ_TYPES):
        return

    if isinstance(statement, exp.Command):
        keyword = str(statement.this or "").upper()
        if keyword in _SAFE_COMMANDS:
            return
        raise PolicyError(f"statement type {keyword or 'UNKNOWN'} is not permitted")

    if isinstance(statement, (exp.Create, exp.Drop)):
        kind = (statement.args.get("kind") or "").upper()
        if kind not in {"TABLE", "VIEW"}:
            raise PolicyError(f"{statement.key.upper()} {kind or 'UNKNOWN'} is not permitted")
        target = _write_target(statement)
        if target is None:
            raise PolicyError("could not determine the target of this statement, rejecting")
        qualified = _schema_prefix(target)
        if not qualified:
            raise PolicyError(
                f"write target '{target.name}' is not schema-qualified; "
                "qualify it with a plugin listed in writable_plugins"
            )
        if not matches_prefix(qualified, policy.writable_plugins):
            raise PolicyError(
                f"writes to '{qualified}' are not permitted; "
                f"add it to writable_plugins to allow this (currently: "
                f"{list(policy.writable_plugins) or 'none'})"
            )
        return

    raise PolicyError(f"statement type {statement.key.upper()} is not permitted")


def _write_target(statement: exp.Expression) -> exp.Table | None:
    target = statement.this
    if isinstance(target, exp.Schema):
        target = target.this
    return target if isinstance(target, exp.Table) else None


def _schema_prefix(table: exp.Table) -> str:
    return ".".join(part for part in (table.catalog, table.db) if part)


def _check_hidden(statement: exp.Expression, policy: Policy) -> None:
    if not policy.hidden_schemas:
        return

    for table in statement.find_all(exp.Table):
        prefix = _schema_prefix(table)
        if prefix and matches_prefix(prefix, policy.hidden_schemas):
            raise PolicyError(f"schema '{prefix}' is hidden by configuration")

    if isinstance(statement, exp.Command):
        # ponytail: sqlglot leaves SHOW's remainder as raw text, so scan it for
        # hidden names. Safe because the tokenizer already stripped comments and
        # string literals cannot appear in a SHOW target. Upgrade to a real parse
        # if Drill's SHOW grammar ever gains an expression argument.
        remainder = str(statement.args.get("expression") or "")
        for entry in policy.hidden_schemas:
            head = entry.split(".")[0]
            if re.search(rf"\b{re.escape(head)}\b", remainder, re.IGNORECASE):
                raise PolicyError(f"schema '{entry}' is hidden by configuration")
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_guard.py -v`
Expected: PASS

If `SHOW SCHEMAS` or `DESCRIBE dfs.tmp.foo` fails to parse in your `sqlglot` version, the fix is in `_SAFE_COMMANDS` / `_READ_TYPES` — do **not** loosen `exp.Command` handling to a blanket allow.

- [ ] **Step 7: Commit**

```bash
git add drill_mcp/guard.py tests/test_guard.py
git commit -m "feat: SQL guard with deny-by-default write policy"
```

---

### Task 3: SQL guard — hidden schemas

**Files:**
- Modify: `drill_mcp/guard.py` (only if the Task 2 tests reveal gaps — `_check_hidden` is already written)
- Test: `tests/test_guard.py` (append)

**Interfaces:**
- Consumes: `guard.Policy`, `guard.check`, `guard.PolicyError` from Task 2
- Produces: no new symbols; hardens existing behavior

- [ ] **Step 1: Write the failing hidden-schema tests**

Append to `tests/test_guard.py`:

```python
HIDDEN = Policy(hidden_schemas=("sys", "INFORMATION_SCHEMA"))


class TestHiddenSchemas:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM sys.options",
            "SELECT * FROM sys.drillbits",
            "SELECT * FROM SYS.OPTIONS",
            "SELECT * FROM INFORMATION_SCHEMA.SCHEMATA",
            "SELECT * FROM information_schema.columns",
            "SELECT * FROM dfs.tmp.a JOIN sys.options ON a.k = sys.options.name",
            "SELECT * FROM (SELECT name FROM sys.options) t",
            "WITH o AS (SELECT * FROM sys.options) SELECT * FROM o",
            "SELECT * FROM dfs.tmp.a UNION SELECT name, val FROM sys.options",
            "SELECT (SELECT count(*) FROM sys.drillbits) AS n FROM dfs.tmp.a",
        ],
    )
    def test_hidden_schema_references_rejected(self, sql):
        with pytest.raises(PolicyError, match="hidden"):
            check(sql, HIDDEN)

    def test_show_tables_in_hidden_schema_rejected(self):
        with pytest.raises(PolicyError, match="hidden"):
            check("SHOW TABLES IN sys", HIDDEN)

    def test_hidden_schema_is_a_no_op_when_unconfigured(self):
        check("SELECT * FROM sys.options", CLOSED)

    def test_non_hidden_schemas_still_permitted(self):
        check("SELECT * FROM dfs.tmp.foo", HIDDEN)

    def test_similarly_named_schema_not_blocked(self):
        check("SELECT * FROM system_metrics.foo", HIDDEN)

    def test_hidden_check_applies_to_ctas_sources(self):
        policy = Policy(writable_plugins=("dfs.tmp",), hidden_schemas=("sys",))
        with pytest.raises(PolicyError, match="hidden"):
            check("CREATE TABLE dfs.tmp.out AS SELECT * FROM sys.options", policy)

    def test_hidden_schema_named_in_a_string_literal_is_fine(self):
        check("SELECT 'sys.options' AS note FROM dfs.tmp.a", HIDDEN)
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_guard.py -k Hidden -v`
Expected: most PASS from Task 2's implementation. Any FAIL is a real gap — fix it in `_check_hidden` before continuing.

Two failures are plausible and both must be fixed rather than accommodated:
- `test_similarly_named_schema_not_blocked` failing means the `\b` regex in the `exp.Command` branch is leaking into non-`SHOW` paths. It should only run for `exp.Command`.
- `test_hidden_schema_named_in_a_string_literal_is_fine` failing means something is scanning raw text where it should be walking `exp.Table` nodes.

- [ ] **Step 3: Verify the full guard suite passes together**

Run: `pytest tests/test_guard.py -v --cov=drill_mcp.guard --cov-report=term-missing`
Expected: PASS, with `guard.py` at 100% line coverage. Add a test for any uncovered line.

- [ ] **Step 4: Commit**

```bash
git add drill_mcp/guard.py tests/test_guard.py
git commit -m "test: hidden schema enforcement in the SQL guard"
```

---

### Task 4: Secret redaction

**Files:**
- Create: `drill_mcp/redact.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Consumes: nothing
- Produces: `drill_mcp.redact.redact(value: Any) -> Any` and `drill_mcp.redact.REDACTED: str`

- [ ] **Step 1: Write the failing tests**

`tests/test_redact.py`:

```python
from drill_mcp.redact import REDACTED, redact


def test_redacts_password_key():
    assert redact({"password": "hunter2"}) == {"password": REDACTED}


def test_redaction_is_case_insensitive():
    assert redact({"PassWord": "hunter2"}) == {"PassWord": REDACTED}


def test_redacts_all_sensitive_key_patterns():
    source = {
        "accessKey": "AKIA",
        "access_key": "AKIA",
        "secretKey": "s",
        "token": "t",
        "credential": "c",
        "privateKey": "p",
        "oauthToken": "o",
    }
    assert all(v == REDACTED for v in redact(source).values())


def test_leaves_innocuous_keys_alone():
    assert redact({"type": "file", "connection": "s3a://bucket"}) == {
        "type": "file",
        "connection": "s3a://bucket",
    }


def test_recurses_into_nested_dicts():
    # Nested under a neutral container on purpose: a key like `credentialsProvider`
    # is itself sensitive-named and gets blanked wholesale, so it cannot double as
    # the vehicle for proving recursion.
    source = {"config": {"aws": {"awsSecretAccessKey": "s"}}}
    assert redact(source)["config"]["aws"]["awsSecretAccessKey"] == REDACTED


def test_blanks_a_credentials_provider_block_wholesale():
    assert redact({"credentialsProvider": {"clientID": "x"}})["credentialsProvider"] == REDACTED


def test_recurses_into_lists():
    source = {"plugins": [{"password": "a"}, {"password": "b"}]}
    assert [p["password"] for p in redact(source)["plugins"]] == [REDACTED, REDACTED]


def test_does_not_mutate_the_input():
    source = {"password": "hunter2"}
    redact(source)
    assert source["password"] == "hunter2"


def test_redacts_whole_subtree_under_a_sensitive_key():
    source = {"credentials": {"user": "alice", "pass": "x"}}
    assert redact(source)["credentials"] == REDACTED


def test_passes_through_scalars():
    assert redact("plain") == "plain"
    assert redact(42) == 42
    assert redact(None) is None


def test_realistic_s3_plugin_config():
    plugin = {
        "name": "s3",
        "config": {
            "type": "file",
            "connection": "s3a://my-bucket",
            "config": {
                "fs.s3a.access.key": "AKIAEXAMPLE",
                "fs.s3a.secret.key": "verysecret",
                "fs.s3a.endpoint": "s3.amazonaws.com",
            },
            "workspaces": {"root": {"location": "/", "writable": False}},
        },
    }
    result = redact(plugin)
    inner = result["config"]["config"]
    assert inner["fs.s3a.access.key"] == REDACTED
    assert inner["fs.s3a.secret.key"] == REDACTED
    assert inner["fs.s3a.endpoint"] == "s3.amazonaws.com"
    assert result["config"]["workspaces"]["root"]["location"] == "/"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_redact.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'drill_mcp.redact'`

- [ ] **Step 3: Implement `drill_mcp/redact.py`**

```python
"""Recursive secret redaction for anything returned to an MCP client.

Storage plugin configurations routinely carry AWS keys, JDBC passwords, and
OAuth tokens. Tool output goes to a model and often on to a third-party API, so
this is a trust boundary and is not configurable off.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"

# Matches anywhere in the key, so `fs.s3a.secret.key` and `awsSecretAccessKey`
# are both caught. Deliberately broad: a false redaction is a cosmetic problem,
# a missed one is a leaked credential.
_SENSITIVE = re.compile(
    r"password|passwd|secret|credential|token|access[._-]?key|private[._-]?key|api[._-]?key",
    re.IGNORECASE,
)


def redact(value: Any) -> Any:
    """Return a copy of `value` with sensitive-looking values replaced."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _SENSITIVE.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_redact.py -v`
Expected: PASS, 10 tests

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/redact.py tests/test_redact.py
git commit -m "feat: recursive secret redaction"
```

---

### Task 5: REST client — authentication and query execution

**Files:**
- Create: `drill_mcp/client_rest.py`
- Test: `tests/test_client_rest.py`

**Interfaces:**
- Consumes: `config.Config`
- Produces:
  - `drill_mcp.client_rest.RestClient(config: Config)` with `close() -> None`
  - `RestClient.query(sql: str, max_rows: int) -> QueryResult`
  - `drill_mcp.client_rest.QueryResult` — dataclass with `columns: list[str]`, `rows: list[dict]`, `query_id: str | None`, `truncated: bool`
  - `drill_mcp.client_rest.DrillError(Exception)`
  - `drill_mcp.client_rest.quote_literal(value: str) -> str` — validates a single identifier and returns it as a SQL literal
  - `drill_mcp.client_rest.quote_literal_path(value: str) -> str` — same, for a dotted schema path like `dfs.tmp`

- [ ] **Step 1: Write the failing tests**

`tests/test_client_rest.py`:

```python
import httpx
import pytest
import respx

from drill_mcp.client_rest import DrillError, RestClient, quote_literal, quote_literal_path
from drill_mcp.config import load_config

BASE = "http://drill:8047"


def make_client(**overrides):
    overrides.setdefault("url", BASE)
    return RestClient(load_config(overrides=overrides))


class TestQuoting:
    """Trust boundary: schema and table names arrive from the model."""

    def test_literal_quotes_a_single_identifier(self):
        assert quote_literal("foo") == "'foo'"

    def test_literal_path_allows_dots(self):
        assert quote_literal_path("dfs.tmp") == "'dfs.tmp'"

    def test_literal_path_allows_ordinary_drill_names(self):
        assert quote_literal_path("my_ws.data-2024") == "'my_ws.data-2024'"

    @pytest.mark.parametrize(
        "bad",
        ["foo'bar", "foo;DROP", "foo bar", "foo\nbar", "", "foo\\bar", "foo`bar", "dfs.tmp"],
    )
    def test_literal_rejects_dangerous_input(self, bad):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_literal(bad)

    @pytest.mark.parametrize(
        "bad",
        ["foo'bar", "foo;DROP", "foo bar", "foo\nbar", "", "..", "foo\\bar", "foo`bar"],
    )
    def test_literal_path_rejects_dangerous_input(self, bad):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_literal_path(bad)


class TestQuery:
    @respx.mock
    def test_posts_sql_with_autolimit(self):
        route = respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(
                200, json={"columns": ["a"], "rows": [{"a": "1"}], "queryId": "q1"}
            )
        )
        result = make_client().query("SELECT 1", max_rows=10)
        assert route.called
        body = route.calls.last.request.read()
        assert b'"queryType": "SQL"' in body or b'"queryType":"SQL"' in body
        assert b"autoLimit" in body
        assert result.columns == ["a"]
        assert result.rows == [{"a": "1"}]
        assert result.query_id == "q1"
        assert result.truncated is False

    @respx.mock
    def test_marks_result_truncated_at_the_cap(self):
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(
                200, json={"columns": ["a"], "rows": [{"a": "1"}, {"a": "2"}]}
            )
        )
        assert make_client().query("SELECT 1", max_rows=2).truncated is True

    @respx.mock
    def test_drill_error_text_is_surfaced(self):
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(500, json={"errorMessage": "VALIDATION ERROR: no such table"})
        )
        with pytest.raises(DrillError, match="no such table"):
            make_client().query("SELECT * FROM nope", max_rows=10)

    @respx.mock
    def test_connection_failure_message_names_the_url_not_the_password(self):
        respx.post(f"{BASE}/query.json").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(DrillError) as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert BASE in str(exc.value)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_timeout_is_reported_clearly(self):
        respx.post(f"{BASE}/query.json").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(DrillError, match="timed out"):
            make_client().query("SELECT 1", max_rows=1)


class TestBasicAuth:
    @respx.mock
    def test_logs_in_before_the_first_query(self):
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": [], "rows": []})
        )
        make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert login.called
        assert b"j_username=alice" in login.calls.last.request.read()

    @respx.mock
    def test_session_is_reused_across_queries(self):
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": [], "rows": []})
        )
        client = make_client(auth="basic", user="alice", password="s3cret")
        client.query("SELECT 1", max_rows=1)
        client.query("SELECT 2", max_rows=1)
        assert login.call_count == 1

    @respx.mock
    def test_reauthenticates_once_on_401(self):
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        query = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                httpx.Response(401),
                httpx.Response(200, json={"columns": ["a"], "rows": []}),
            ]
        )
        result = make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert result.columns == ["a"]
        assert login.call_count == 2
        assert query.call_count == 2

    @respx.mock
    def test_gives_up_after_one_retry(self):
        respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        respx.post(f"{BASE}/query.json").mock(return_value=httpx.Response(401))
        with pytest.raises(DrillError, match="authentication"):
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)

    @respx.mock
    def test_login_failure_is_reported(self):
        respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(401))
        with pytest.raises(DrillError, match="authentication"):
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)

    @respx.mock
    def test_no_login_when_auth_is_none(self):
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": [], "rows": []})
        )
        make_client().query("SELECT 1", max_rows=1)
        assert not login.called
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_client_rest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'drill_mcp.client_rest'`

- [ ] **Step 3: Implement the auth and query half of `drill_mcp/client_rest.py`**

```python
"""Drill REST backend.

Talks to a Drillbit's HTTP endpoints. Metadata methods issue INFORMATION_SCHEMA
queries directly and deliberately bypass `guard.py` — the guard governs SQL that
originated from the model, not SQL this module composes itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Config

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_$-]+$")


class DrillError(Exception):
    """Any failure talking to Drill: connection, auth, or query error."""


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    query_id: str | None = None
    truncated: bool = False


def quote_literal(value: str) -> str:
    """Return one identifier as a single-quoted SQL literal, rejecting unsafe input.

    Trust boundary: schema and table names arrive from the model and are
    interpolated into INFORMATION_SCHEMA queries. Drill's REST API has no bind
    parameters, so anything outside the safe character set is rejected rather
    than escaped.
    """
    if not _IDENTIFIER.match(value):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"'{value}'"


def quote_literal_path(value: str) -> str:
    """Same as `quote_literal`, but permits a dotted schema path like `dfs.tmp`."""
    parts = value.split(".")
    if not parts or any(not _IDENTIFIER.match(part) for part in parts):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"'{value}'"


class RestClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._authenticated = False
        auth = None
        if config.auth == "kerberos":
            try:
                from httpx_gssapi import HTTPSPNEGOAuth
            except ImportError as exc:  # pragma: no cover - exercised in Task 7 style
                raise DrillError(
                    "auth: kerberos requires the kerberos extra: pip install drill-mcp[kerberos]"
                ) from exc
            auth = HTTPSPNEGOAuth()
        self._http = httpx.Client(
            base_url=config.url,
            timeout=config.timeout_seconds,
            auth=auth,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._http.close()

    # -- transport ---------------------------------------------------------

    def _login(self) -> None:
        if self._config.auth != "basic":
            self._authenticated = True
            return
        try:
            response = self._http.post(
                "/j_security_check",
                data={
                    "j_username": self._config.user,
                    "j_password": self._config.password,
                },
            )
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from exc
        if response.status_code >= 400 or "j_security_check" in str(response.url):
            raise DrillError(
                f"authentication failed for user {self._config.user!r} at {self._config.url}"
            )
        self._authenticated = True

    def _transport_error(self, exc: httpx.HTTPError) -> DrillError:
        if isinstance(exc, httpx.TimeoutException):
            return DrillError(
                f"request to {self._config.url} timed out after "
                f"{self._config.timeout_seconds}s"
            )
        return DrillError(
            f"could not reach Drill at {self._config.url} "
            f"(auth mode: {self._config.auth}): {type(exc).__name__}"
        )

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if not self._authenticated:
            self._login()
        try:
            response = self._http.request(method, path, **kwargs)
            if response.status_code == 401 and self._config.auth == "basic":
                self._authenticated = False
                self._login()
                response = self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise self._transport_error(exc) from exc

        if response.status_code == 401:
            raise DrillError(
                f"authentication rejected by Drill at {self._config.url} "
                f"for user {self._config.user!r}"
            )
        if response.status_code >= 400:
            raise DrillError(_error_text(response))
        return response

    # -- queries -----------------------------------------------------------

    def query(self, sql: str, max_rows: int) -> QueryResult:
        response = self._request(
            "POST",
            "/query.json",
            json={"queryType": "SQL", "query": sql, "autoLimit": max_rows},
        )
        payload = response.json()
        rows = payload.get("rows") or []
        return QueryResult(
            columns=payload.get("columns") or [],
            rows=rows,
            query_id=payload.get("queryId"),
            truncated=len(rows) >= max_rows,
        )


def _error_text(response: httpx.Response) -> str:
    """Drill's own error text is what a model needs to fix its SQL. Truncate it."""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    message = ""
    if isinstance(payload, dict):
        message = payload.get("errorMessage") or payload.get("message") or ""
    if not message:
        message = response.text
    message = " ".join(message.split())
    if len(message) > 2000:
        message = message[:2000] + " ... [truncated]"
    return message or f"Drill returned HTTP {response.status_code}"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_client_rest.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/client_rest.py tests/test_client_rest.py
git commit -m "feat: Drill REST client with auth and query execution"
```

---

### Task 6: REST client — metadata and management endpoints

**Files:**
- Modify: `drill_mcp/client_rest.py`
- Test: `tests/test_client_rest.py` (append)

**Interfaces:**
- Consumes: `RestClient`, `QueryResult`, `DrillError`, `quote_literal`, `quote_literal_path` from Task 5; `redact.redact` from Task 4
- Produces:
  - `drill_mcp.client_rest.quote_identifier_path(value: str) -> str` — validates a
    dotted path and returns it backtick-quoted (`dfs.tmp` → `` `dfs`.`tmp` ``).
    Needed for `SHOW FILES FROM` and `DESCRIBE`, which take identifiers rather
    than string literals. Same character allowlist as `quote_literal_path`;
    rejects rather than escapes.
- Produces, all on `RestClient`:
  - `plugin_type(schema: str) -> str | None` — the storage plugin TYPE backing a schema
  - `schemas() -> list[dict]` — keys `name`, `type`
  - `tables(schema: str) -> list[dict]` — keys `name`, `type`
  - `columns(schema: str, table: str) -> list[dict]` — keys `name`, `data_type`, `nullable`

**Why `tables` and `columns` branch on plugin type.** File-based plugins (`dfs`,
`s3`) do not register their contents in `INFORMATION_SCHEMA`. Querying
`INFORMATION_SCHEMA.`TABLES`` for `dfs.tmp` returns an empty list that looks
exactly like an empty workspace, so file plugins need `SHOW FILES FROM` instead,
and `DESCRIBE` rather than `INFORMATION_SCHEMA.`COLUMNS``. `sqlalchemy-drill`'s
`get_table_names` and `get_columns` branch the same way. `DESCRIBE` is chosen
over that dialect's `SELECT * ... LIMIT 1` fallback deliberately: reading a row
of user data to answer a metadata question is the wrong trade here.
  - `storage_plugins() -> list[dict]` — redacted
  - `cluster_status() -> dict`
  - `profiles(limit: int) -> list[dict]`
  - `profile(query_id: str) -> dict`
  - `cancel_query(query_id: str) -> str`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_client_rest.py`:

```python
def query_response(columns, rows):
    return httpx.Response(200, json={"columns": columns, "rows": rows, "queryId": "q"})


class TestMetadata:
    @respx.mock
    def test_schemas_queries_information_schema(self):
        route = respx.post(f"{BASE}/query.json").mock(
            return_value=query_response(
                ["SCHEMA_NAME", "TYPE"], [{"SCHEMA_NAME": "dfs.tmp", "TYPE": "file"}]
            )
        )
        assert make_client().schemas() == [{"name": "dfs.tmp", "type": "file"}]
        assert b"INFORMATION_SCHEMA" in route.calls.last.request.read()

    @respx.mock
    def test_tables_filters_by_schema(self):
        route = respx.post(f"{BASE}/query.json").mock(
            return_value=query_response(
                ["TABLE_NAME", "TABLE_TYPE"], [{"TABLE_NAME": "t", "TABLE_TYPE": "TABLE"}]
            )
        )
        assert make_client().tables("dfs.tmp") == [{"name": "t", "type": "TABLE"}]
        assert b"'dfs.tmp'" in route.calls.last.request.read()

    @respx.mock
    def test_columns_returns_name_type_nullable(self):
        respx.post(f"{BASE}/query.json").mock(
            return_value=query_response(
                ["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE"],
                [{"COLUMN_NAME": "id", "DATA_TYPE": "INTEGER", "IS_NULLABLE": "YES"}],
            )
        )
        assert make_client().columns("dfs.tmp", "t") == [
            {"name": "id", "data_type": "INTEGER", "nullable": True}
        ]

    @respx.mock
    def test_metadata_rejects_injection_in_schema_name(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            make_client().tables("dfs'; DROP TABLE x --")


class TestFilePluginMetadata:
    """File plugins are absent from INFORMATION_SCHEMA; they need SHOW FILES."""

    @staticmethod
    def _schemata(plugin_type):
        return query_response(["SCHEMA_NAME", "TYPE"], [{"SCHEMA_NAME": "dfs.tmp", "TYPE": plugin_type}])

    @respx.mock
    def test_tables_uses_show_files_for_a_file_plugin(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(["name", "isDirectory"], [{"name": "sales.csv", "isDirectory": "false"}]),
            ]
        )
        assert make_client().tables("dfs.tmp") == [{"name": "sales.csv", "type": "TABLE"}]
        assert b"SHOW FILES FROM" in route.calls[1].request.read()

    @respx.mock
    def test_show_files_marks_directories(self):
        respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(["name", "isDirectory"], [{"name": "year=2024", "isDirectory": "true"}]),
            ]
        )
        assert make_client().tables("dfs.tmp")[0]["type"] == "DIRECTORY"

    @respx.mock
    def test_show_files_strips_the_view_drill_suffix(self):
        respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(["name", "isDirectory"], [{"name": "top_sales.view.drill", "isDirectory": "false"}]),
            ]
        )
        assert make_client().tables("dfs.tmp") == [{"name": "top_sales", "type": "VIEW"}]

    @respx.mock
    def test_tables_uses_information_schema_for_a_non_file_plugin(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("jdbc"),
                query_response(["TABLE_NAME", "TABLE_TYPE"], [{"TABLE_NAME": "t", "TABLE_TYPE": "TABLE"}]),
            ]
        )
        assert make_client().tables("mysql.app") == [{"name": "t", "type": "TABLE"}]
        assert b"INFORMATION_SCHEMA" in route.calls[1].request.read()

    @respx.mock
    def test_columns_uses_describe_for_a_file_plugin(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(
                    ["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE"],
                    [{"COLUMN_NAME": "id", "DATA_TYPE": "BIGINT", "IS_NULLABLE": "YES"}],
                ),
            ]
        )
        assert make_client().columns("dfs.tmp", "sales.csv") == [
            {"name": "id", "data_type": "BIGINT", "nullable": True}
        ]
        body = route.calls[1].request.read()
        assert b"DESCRIBE" in body
        # Metadata-only: never read user rows to answer a metadata question.
        assert b"LIMIT 1" not in body
        assert b"SELECT *" not in body

    @respx.mock
    def test_columns_uses_information_schema_for_a_non_file_plugin(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("jdbc"),
                query_response(
                    ["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE"],
                    [{"COLUMN_NAME": "id", "DATA_TYPE": "INTEGER", "IS_NULLABLE": "NO"}],
                ),
            ]
        )
        result = make_client().columns("mysql.app", "t")
        assert result == [{"name": "id", "data_type": "INTEGER", "nullable": False}]
        assert b"INFORMATION_SCHEMA" in route.calls[1].request.read()

    @respx.mock
    def test_unknown_plugin_type_falls_back_to_information_schema(self):
        respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                query_response(["SCHEMA_NAME", "TYPE"], []),
                query_response(["TABLE_NAME", "TABLE_TYPE"], []),
            ]
        )
        assert make_client().tables("nope") == []

    @respx.mock
    def test_show_files_path_still_rejects_injection(self):
        respx.post(f"{BASE}/query.json").mock(return_value=self._schemata("file"))
        with pytest.raises(DrillError, match="invalid identifier"):
            make_client().tables("dfs`; DROP TABLE x --")

    @respx.mock
    def test_metadata_rejects_injection_in_table_name(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            make_client().columns("dfs.tmp", "t' OR '1'='1")


class TestManagement:
    @respx.mock
    def test_storage_plugins_are_redacted(self):
        respx.get(f"{BASE}/storage.json").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "name": "s3",
                        "config": {"type": "file", "fs.s3a.secret.key": "verysecret"},
                    }
                ],
            )
        )
        plugins = make_client().storage_plugins()
        assert plugins[0]["config"]["fs.s3a.secret.key"] == "***REDACTED***"
        assert plugins[0]["name"] == "s3"

    @respx.mock
    def test_cluster_status_merges_cluster_and_status(self):
        respx.get(f"{BASE}/cluster.json").mock(
            return_value=httpx.Response(200, json={"drillbits": [{"address": "n1"}]})
        )
        respx.get(f"{BASE}/status.json").mock(
            return_value=httpx.Response(200, json={"status": "Running!"})
        )
        result = make_client().cluster_status()
        assert result["drillbits"] == [{"address": "n1"}]
        assert result["status"] == "Running!"

    @respx.mock
    def test_profiles_are_limited(self):
        respx.get(f"{BASE}/profiles.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "finishedQueries": [{"queryId": f"q{i}"} for i in range(10)],
                    "runningQueries": [],
                },
            )
        )
        assert len(make_client().profiles(limit=3)) == 3

    @respx.mock
    def test_profiles_include_running_queries_first(self):
        respx.get(f"{BASE}/profiles.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "runningQueries": [{"queryId": "live"}],
                    "finishedQueries": [{"queryId": "done"}],
                },
            )
        )
        assert make_client().profiles(limit=5)[0]["queryId"] == "live"

    @respx.mock
    def test_profile_fetches_one_query(self):
        respx.get(f"{BASE}/profiles/abc.json").mock(
            return_value=httpx.Response(200, json={"queryId": "abc", "state": "COMPLETED"})
        )
        assert make_client().profile("abc")["state"] == "COMPLETED"

    @respx.mock
    def test_profile_rejects_a_malformed_query_id(self):
        with pytest.raises(DrillError, match="invalid"):
            make_client().profile("../../etc/passwd")

    @respx.mock
    def test_cancel_query(self):
        route = respx.get(f"{BASE}/profiles/cancel/abc").mock(
            return_value=httpx.Response(200, text="Cancelled query abc")
        )
        assert "abc" in make_client().cancel_query("abc")
        assert route.called

    @respx.mock
    def test_cancel_rejects_a_malformed_query_id(self):
        with pytest.raises(DrillError, match="invalid"):
            make_client().cancel_query("abc; rm -rf /")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_client_rest.py -k "Metadata or Management" -v`
Expected: FAIL — `AttributeError: 'RestClient' object has no attribute 'schemas'`

- [ ] **Step 3: Add the metadata and management methods**

Add this import near the top of `drill_mcp/client_rest.py`:

```python
from .redact import redact
```

Add a query-id validator beside `quote_literal`:

```python
_QUERY_ID = re.compile(r"^[A-Za-z0-9-]+$")


def _check_query_id(query_id: str) -> str:
    if not _QUERY_ID.match(query_id):
        raise DrillError(f"invalid query id: {query_id!r}")
    return query_id
```

Append these methods to `RestClient`:

```python
    # -- metadata ----------------------------------------------------------

    def schemas(self) -> list[dict[str, Any]]:
        result = self.query(
            "SELECT SCHEMA_NAME, TYPE FROM INFORMATION_SCHEMA.SCHEMATA "
            "ORDER BY SCHEMA_NAME",
            max_rows=10_000,
        )
        return [
            {"name": row.get("SCHEMA_NAME"), "type": row.get("TYPE")}
            for row in result.rows
        ]

    def plugin_type(self, schema: str) -> str | None:
        """Return the storage plugin TYPE backing `schema`, or None if unknown.

        File-based plugins (`dfs`, `s3`) do not register their contents in
        INFORMATION_SCHEMA, so `tables` and `columns` must branch on this.
        """
        result = self.query(
            "SELECT SCHEMA_NAME, TYPE FROM INFORMATION_SCHEMA.`SCHEMATA` "
            f"WHERE SCHEMA_NAME = {quote_literal_path(schema)}",
            max_rows=1,
        )
        return result.rows[0].get("TYPE") if result.rows else None

    def tables(self, schema: str) -> list[dict[str, Any]]:
        # File plugins are absent from INFORMATION_SCHEMA.`TABLES`; querying it
        # for `dfs.tmp` returns an empty list that looks like an empty workspace.
        # `SHOW FILES` is the only way to enumerate them. sqlalchemy-drill's
        # get_table_names branches the same way.
        if self.plugin_type(schema) == "file":
            result = self.query(
                f"SHOW FILES FROM {quote_identifier_path(schema)}", max_rows=10_000
            )
            tables: list[dict[str, Any]] = []
            for row in result.rows:
                name = row.get("name")
                if not name:
                    continue
                # Drill stores a view as a `<name>.view.drill` file in the workspace.
                if name.endswith(".view.drill"):
                    tables.append({"name": name[: -len(".view.drill")], "type": "VIEW"})
                else:
                    is_dir = str(row.get("isDirectory", "")).lower() == "true"
                    tables.append({"name": name, "type": "DIRECTORY" if is_dir else "TABLE"})
            return sorted(tables, key=lambda t: t["name"])

        result = self.query(
            "SELECT TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.`TABLES` "
            f"WHERE TABLE_SCHEMA = {quote_literal_path(schema)} ORDER BY TABLE_NAME",
            max_rows=10_000,
        )
        return [
            {"name": row.get("TABLE_NAME"), "type": row.get("TABLE_TYPE")}
            for row in result.rows
        ]

    def columns(self, schema: str, table: str) -> list[dict[str, Any]]:
        # Same split: file plugins have dynamic schemas and no
        # INFORMATION_SCHEMA.`COLUMNS` rows. DESCRIBE is metadata-only —
        # deliberately NOT a `SELECT * ... LIMIT 1` probe, which would read user
        # data to answer a metadata question.
        if self.plugin_type(schema) == "file":
            result = self.query(
                f"DESCRIBE {quote_identifier_path(schema + '.' + table)}",
                max_rows=10_000,
            )
            return [
                {
                    "name": row.get("COLUMN_NAME"),
                    "data_type": row.get("DATA_TYPE"),
                    "nullable": str(row.get("IS_NULLABLE", "")).upper() == "YES",
                }
                for row in result.rows
            ]

        result = self.query(
            "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM INFORMATION_SCHEMA.`COLUMNS` "
            f"WHERE TABLE_SCHEMA = {quote_literal_path(schema)} "
            f"AND TABLE_NAME = {quote_literal(table)} ORDER BY ORDINAL_POSITION",
            max_rows=10_000,
        )
        return [
            {
                "name": row.get("COLUMN_NAME"),
                "data_type": row.get("DATA_TYPE"),
                "nullable": str(row.get("IS_NULLABLE", "")).upper() == "YES",
            }
            for row in result.rows
        ]

    # -- management --------------------------------------------------------

    def storage_plugins(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/storage.json").json()
        return redact(payload)

    def cluster_status(self) -> dict[str, Any]:
        cluster = self._request("GET", "/cluster.json").json()
        status = self._request("GET", "/status.json").json()
        merged = dict(cluster) if isinstance(cluster, dict) else {"cluster": cluster}
        if isinstance(status, dict):
            merged.update(status)
        else:
            merged["status"] = status
        return merged

    def profiles(self, limit: int) -> list[dict[str, Any]]:
        payload = self._request("GET", "/profiles.json").json()
        running = payload.get("runningQueries") or []
        finished = payload.get("finishedQueries") or []
        return (list(running) + list(finished))[:limit]

    def profile(self, query_id: str) -> dict[str, Any]:
        _check_query_id(query_id)
        return self._request("GET", f"/profiles/{query_id}.json").json()

    def cancel_query(self, query_id: str) -> str:
        _check_query_id(query_id)
        return self._request("GET", f"/profiles/cancel/{query_id}").text
```

`quote_literal` and `quote_literal_path` already exist from Task 5. This task
adds the query-id validator, the methods above, and one more quoting helper —
`SHOW FILES FROM` and `DESCRIBE` take *identifiers*, not string literals, so
they need backtick quoting rather than `'...'`:

```python
def quote_identifier_path(value: str) -> str:
    """Validate a dotted path and return it backtick-quoted: dfs.tmp -> `dfs`.`tmp`.

    Same trust boundary as quote_literal_path — these values arrive from the
    model and are interpolated into SQL. Reject rather than escape.
    """
    parts = value.split(".")
    if any(not _IDENTIFIER.fullmatch(part) for part in parts):
        raise DrillError(f"invalid identifier: {value!r}")
    return ".".join(f"`{part}`" for part in parts)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_client_rest.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/client_rest.py tests/test_client_rest.py
git commit -m "feat: metadata and management endpoints on the REST client"
```

---

### Task 7: JDBC client

**Files:**
- Create: `drill_mcp/client_jdbc.py`
- Test: `tests/test_client_jdbc.py`

**Interfaces:**
- Consumes: `config.Config`, `client_rest.QueryResult`, `client_rest.DrillError`
- Produces: `drill_mcp.client_jdbc.JdbcClient(config: Config)` with `query`, `plugin_type`, `schemas`, `tables`, `columns`, `close` — the same signatures as `RestClient`. Management methods are **not** implemented.
- Also produces, by extraction in `client_rest.py`:
  - `fetch_plugin_type(query, schema) -> str | None`
  - `fetch_schemas(query) -> list[dict]`
  - `fetch_tables(query, schema) -> list[dict]`
  - `fetch_columns(query, schema, table) -> list[dict]`

  where `query` is any callable `(sql: str, max_rows: int) -> QueryResult`.

**This task starts with a refactor, then adds the JDBC client.** Task 6 implemented
the metadata methods directly on `RestClient`. They are pure SQL-building plus
row-mapping over `query()` — including the file-plugin branching — and the JDBC
client needs exactly the same behavior. Duplicating ~80 lines of security-relevant
identifier quoting and plugin-type branching into a second class would be a defect,
not a convenience.

So: first extract Task 6's `plugin_type`/`schemas`/`tables`/`columns` bodies into
module-level `fetch_*` functions in `client_rest.py` that take a query callable,
and reduce `RestClient`'s methods to one-line delegations. Task 6's existing tests
must keep passing **unchanged** — that is the proof the extraction is behavior-
preserving. Only then add `JdbcClient`, delegating to the same functions.

The second consumer is what justifies the abstraction; extracting before it existed
would have been speculative.

**Note for the implementer:** this task never imports a real JVM. `jaydebeapi` is mocked in tests via `monkeypatch.setitem(sys.modules, ...)`, so the suite runs without the `jdbc` extra installed.

- [ ] **Step 1: Write the failing tests**

`tests/test_client_jdbc.py`:

```python
import sys
from unittest.mock import MagicMock

import pytest

from drill_mcp.client_jdbc import JdbcClient
from drill_mcp.client_rest import DrillError
from drill_mcp.config import load_config


@pytest.fixture
def fake_jaydebeapi(monkeypatch):
    module = MagicMock()
    cursor = MagicMock()
    cursor.description = [("a", None), ("b", None)]
    cursor.fetchmany.return_value = [(1, "x")]
    connection = MagicMock()
    connection.cursor.return_value = cursor
    module.connect.return_value = connection
    monkeypatch.setitem(sys.modules, "jaydebeapi", module)
    return module


def make_client(**overrides):
    overrides.setdefault("backend", "jdbc")
    overrides.setdefault("jdbc_driver_path", "/opt/drill-jdbc-all.jar")
    return JdbcClient(load_config(overrides=overrides))


def test_clear_error_when_extra_is_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "jaydebeapi", None)
    with pytest.raises(DrillError, match=r"drill-mcp\[jdbc\]"):
        make_client().query("SELECT 1", max_rows=1)


def test_connect_uses_the_configured_driver_and_url(fake_jaydebeapi):
    make_client(url="http://drill:8047").query("SELECT 1", max_rows=1)
    args = fake_jaydebeapi.connect.call_args
    assert args.args[0] == "org.apache.drill.jdbc.Driver"
    assert args.args[1].startswith("jdbc:drill:")
    assert args.kwargs["jars"] == ["/opt/drill-jdbc-all.jar"]


def test_query_returns_columns_and_rows(fake_jaydebeapi):
    result = make_client().query("SELECT 1", max_rows=10)
    assert result.columns == ["a", "b"]
    assert result.rows == [{"a": 1, "b": "x"}]
    assert result.truncated is False


def test_query_respects_max_rows(fake_jaydebeapi):
    cursor = fake_jaydebeapi.connect.return_value.cursor.return_value
    cursor.fetchmany.return_value = [(1, "x"), (2, "y")]
    result = make_client().query("SELECT 1", max_rows=2)
    cursor.fetchmany.assert_called_with(2)
    assert result.truncated is True


def test_connection_is_reused(fake_jaydebeapi):
    client = make_client()
    client.query("SELECT 1", max_rows=1)
    client.query("SELECT 2", max_rows=1)
    assert fake_jaydebeapi.connect.call_count == 1


def test_basic_auth_credentials_are_passed(fake_jaydebeapi):
    make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
    assert fake_jaydebeapi.connect.call_args.args[2] == ["alice", "s3cret"]


def test_kerberos_sets_the_auth_property(fake_jaydebeapi):
    make_client(auth="kerberos").query("SELECT 1", max_rows=1)
    assert "auth=kerberos" in fake_jaydebeapi.connect.call_args.args[1]


def test_schemas_uses_information_schema(fake_jaydebeapi):
    cursor = fake_jaydebeapi.connect.return_value.cursor.return_value
    cursor.description = [("SCHEMA_NAME", None), ("TYPE", None)]
    cursor.fetchmany.return_value = [("dfs.tmp", "file")]
    assert make_client().schemas() == [{"name": "dfs.tmp", "type": "file"}]


def test_tables_rejects_injection(fake_jaydebeapi):
    with pytest.raises(DrillError, match="invalid identifier"):
        make_client().tables("dfs'; DROP TABLE x --")


def test_driver_error_is_wrapped(fake_jaydebeapi):
    fake_jaydebeapi.connect.side_effect = RuntimeError("no route to host")
    with pytest.raises(DrillError, match="no route to host"):
        make_client().query("SELECT 1", max_rows=1)


def test_close_closes_the_connection(fake_jaydebeapi):
    client = make_client()
    client.query("SELECT 1", max_rows=1)
    client.close()
    fake_jaydebeapi.connect.return_value.close.assert_called_once()


def test_close_is_safe_before_connecting():
    make_client().close()  # does not raise
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_client_jdbc.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'drill_mcp.client_jdbc'`

- [ ] **Step 3: Implement `drill_mcp/client_jdbc.py`**

```python
"""Drill JDBC backend.

Optional, installed via `pip install drill-mcp[jdbc]`. It exists mainly because
Kerberos is materially less painful through the Drill JDBC driver than through
Python SPNEGO. Query and metadata only — management endpoints are REST-only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .client_rest import DrillError, QueryResult, quote_literal, quote_literal_path
from .config import Config

DRIVER_CLASS = "org.apache.drill.jdbc.Driver"


class JdbcClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._connection: Any = None

    # -- connection --------------------------------------------------------

    def _jdbc_url(self) -> str:
        host = urlparse(self._config.url)
        netloc = host.netloc or host.path
        url = f"jdbc:drill:drillbit={netloc}"
        if self._config.auth == "kerberos":
            url += ";auth=kerberos"
        return url

    def _connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import jaydebeapi
        except ImportError as exc:
            raise DrillError(
                "the JDBC backend requires the jdbc extra: pip install drill-mcp[jdbc]"
            ) from exc
        if jaydebeapi is None:
            raise DrillError(
                "the JDBC backend requires the jdbc extra: pip install drill-mcp[jdbc]"
            )
        credentials = (
            [self._config.user, self._config.password]
            if self._config.auth == "basic"
            else []
        )
        try:
            self._connection = jaydebeapi.connect(
                DRIVER_CLASS,
                self._jdbc_url(),
                credentials,
                jars=[self._config.jdbc_driver_path],
            )
        except Exception as exc:
            raise DrillError(f"could not connect to Drill over JDBC: {exc}") from exc
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # -- queries -----------------------------------------------------------

    def query(self, sql: str, max_rows: int) -> QueryResult:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            cursor.execute(sql)
            rows = cursor.fetchmany(max_rows)
            columns = [description[0] for description in cursor.description or []]
        except DrillError:
            raise
        except Exception as exc:
            raise DrillError(str(exc)) from exc
        return QueryResult(
            columns=columns,
            rows=[dict(zip(columns, row)) for row in rows],
            truncated=len(rows) >= max_rows,
        )

    # -- metadata ----------------------------------------------------------

    # Metadata is identical for both backends: it is plain SQL over a `query`
    # callable, including the file-plugin branching. Rather than duplicate it,
    # Task 6's implementations are extracted into module-level functions in
    # `client_rest.py` that take a query callable, and both clients delegate.
    # This is the moment to extract — the second consumer is what justifies it.

    def plugin_type(self, schema: str) -> str | None:
        return fetch_plugin_type(self.query, schema)

    def schemas(self) -> list[dict[str, Any]]:
        return fetch_schemas(self.query)

    def tables(self, schema: str) -> list[dict[str, Any]]:
        return fetch_tables(self.query, schema)

    def columns(self, schema: str, table: str) -> list[dict[str, Any]]:
        return fetch_columns(self.query, schema, table)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_client_jdbc.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/client_jdbc.py tests/test_client_jdbc.py
git commit -m "feat: optional JDBC backend"
```

---

### Task 8: Tool layer — query and metadata tools

**Files:**
- Create: `drill_mcp/server.py`
- Test: `tests/test_server.py`

**Interfaces:**
- Consumes: `config.Config`, `guard.Policy`/`check`/`PolicyError`, `client_rest.RestClient`/`DrillError`, `client_jdbc.JdbcClient`
- Produces:
  - `drill_mcp.server.DrillTools(config: Config, client)` with methods `run_query(sql: str, max_rows: int | None = None) -> dict`, `list_schemas() -> list[dict]`, `list_tables(schema: str) -> list[dict]`, `describe_table(schema: str, table: str) -> list[dict]`
  - `drill_mcp.server.ToolError(Exception)` — the single error type surfaced to MCP clients

**Design note:** tool bodies live on a plain class so they are unit-testable without an MCP session. `build_server` in Task 9 registers the bound methods with FastMCP.

- [ ] **Step 1: Write the failing tests**

`tests/test_server.py`:

```python
from unittest.mock import MagicMock

import pytest

from drill_mcp.client_rest import DrillError, QueryResult
from drill_mcp.config import load_config
from drill_mcp.server import DrillTools, ToolError


def make_tools(client=None, **overrides):
    client = client or MagicMock()
    return DrillTools(load_config(overrides=overrides), client)


class TestRunQuery:
    def test_returns_columns_rows_and_query_id(self):
        client = MagicMock()
        client.query.return_value = QueryResult(["a"], [{"a": 1}], "q1", False)
        result = make_tools(client).run_query("SELECT 1")
        assert result["columns"] == ["a"]
        assert result["rows"] == [{"a": 1}]
        assert result["query_id"] == "q1"
        assert result["truncated"] is False

    def test_applies_the_configured_row_cap(self):
        client = MagicMock()
        client.query.return_value = QueryResult()
        make_tools(client, max_rows=100).run_query("SELECT 1")
        assert client.query.call_args.kwargs["max_rows"] == 100

    def test_caller_may_lower_the_cap(self):
        client = MagicMock()
        client.query.return_value = QueryResult()
        make_tools(client, max_rows=100).run_query("SELECT 1", max_rows=10)
        assert client.query.call_args.kwargs["max_rows"] == 10

    def test_caller_may_not_raise_the_cap(self):
        client = MagicMock()
        client.query.return_value = QueryResult()
        make_tools(client, max_rows=100).run_query("SELECT 1", max_rows=10_000)
        assert client.query.call_args.kwargs["max_rows"] == 100

    def test_truncation_is_reported(self):
        client = MagicMock()
        client.query.return_value = QueryResult(["a"], [{"a": 1}], None, True)
        result = make_tools(client, max_rows=1).run_query("SELECT 1")
        assert result["truncated"] is True
        assert "truncated" in result["note"].lower()

    def test_write_is_rejected_before_reaching_the_client(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="writable_plugins"):
            make_tools(client).run_query("CREATE TABLE dfs.tmp.x AS SELECT 1")
        client.query.assert_not_called()

    def test_write_is_allowed_when_the_plugin_is_writable(self):
        client = MagicMock()
        client.query.return_value = QueryResult()
        make_tools(client, writable_plugins=["dfs.tmp"]).run_query(
            "CREATE TABLE dfs.tmp.x AS SELECT 1"
        )
        client.query.assert_called_once()

    def test_hidden_schema_is_rejected_before_reaching_the_client(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="hidden"):
            make_tools(client, hidden_schemas=["sys"]).run_query("SELECT * FROM sys.options")
        client.query.assert_not_called()

    def test_drill_errors_are_surfaced_as_tool_errors(self):
        client = MagicMock()
        client.query.side_effect = DrillError("VALIDATION ERROR: no such table")
        with pytest.raises(ToolError, match="no such table"):
            make_tools(client).run_query("SELECT * FROM nope")


class TestListSchemas:
    def test_returns_all_schemas_by_default(self):
        client = MagicMock()
        client.schemas.return_value = [{"name": "dfs.tmp"}, {"name": "sys"}]
        assert len(make_tools(client).list_schemas()) == 2

    def test_filters_hidden_schemas(self):
        client = MagicMock()
        client.schemas.return_value = [
            {"name": "dfs.tmp"},
            {"name": "sys"},
            {"name": "INFORMATION_SCHEMA"},
        ]
        result = make_tools(client, hidden_schemas=["sys", "INFORMATION_SCHEMA"]).list_schemas()
        assert [s["name"] for s in result] == ["dfs.tmp"]

    def test_filtering_is_case_insensitive(self):
        client = MagicMock()
        client.schemas.return_value = [{"name": "SYS"}, {"name": "dfs.tmp"}]
        result = make_tools(client, hidden_schemas=["sys"]).list_schemas()
        assert [s["name"] for s in result] == ["dfs.tmp"]

    def test_filters_child_schemas_of_a_hidden_parent(self):
        client = MagicMock()
        client.schemas.return_value = [{"name": "sys.mem"}, {"name": "dfs.tmp"}]
        result = make_tools(client, hidden_schemas=["sys"]).list_schemas()
        assert [s["name"] for s in result] == ["dfs.tmp"]


class TestListTables:
    def test_lists_tables(self):
        client = MagicMock()
        client.tables.return_value = [{"name": "t", "type": "TABLE"}]
        assert make_tools(client).list_tables("dfs.tmp") == [{"name": "t", "type": "TABLE"}]

    def test_hidden_schema_is_refused(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="hidden"):
            make_tools(client, hidden_schemas=["sys"]).list_tables("sys")
        client.tables.assert_not_called()

    def test_information_schema_still_works_internally_when_hidden(self):
        """Hiding INFORMATION_SCHEMA must not break metadata tools."""
        client = MagicMock()
        client.tables.return_value = [{"name": "t", "type": "TABLE"}]
        tools = make_tools(client, hidden_schemas=["INFORMATION_SCHEMA"])
        assert tools.list_tables("dfs.tmp") == [{"name": "t", "type": "TABLE"}]


class TestDescribeTable:
    def test_describes_columns(self):
        client = MagicMock()
        client.columns.return_value = [{"name": "id", "data_type": "INTEGER", "nullable": True}]
        assert make_tools(client).describe_table("dfs.tmp", "t")[0]["name"] == "id"

    def test_hidden_schema_is_refused(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="hidden"):
            make_tools(client, hidden_schemas=["sys"]).describe_table("sys", "options")
        client.columns.assert_not_called()

    def test_unknown_table_error_is_surfaced(self):
        client = MagicMock()
        client.columns.side_effect = DrillError("invalid identifier")
        with pytest.raises(ToolError, match="invalid identifier"):
            make_tools(client).describe_table("dfs.tmp", "nope")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_server.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'drill_mcp.server'`

- [ ] **Step 3: Implement the tool layer in `drill_mcp/server.py`**

```python
"""MCP tool layer.

Tool bodies live on `DrillTools` as plain methods so they can be unit-tested
without standing up an MCP session; `build_server` registers the bound methods
with FastMCP.
"""

from __future__ import annotations

from typing import Any

from .client_rest import DrillError
from .config import Config
from .guard import Policy, PolicyError, check, matches_prefix


class ToolError(Exception):
    """The single error type surfaced to MCP clients. Never carries a traceback."""


class DrillTools:
    def __init__(self, config: Config, client: Any) -> None:
        self._config = config
        self._client = client
        self._policy = Policy.from_config(config)

    # -- helpers -----------------------------------------------------------

    def _effective_max_rows(self, requested: int | None) -> int:
        cap = self._config.max_rows
        if requested is None or requested <= 0:
            return cap
        return min(requested, cap)

    def _refuse_if_hidden(self, schema: str) -> None:
        if matches_prefix(schema, self._policy.hidden_schemas):
            raise ToolError(f"schema '{schema}' is hidden by configuration")

    def _visible(self, schema: str | None) -> bool:
        return not (schema and matches_prefix(schema, self._policy.hidden_schemas))

    # -- tools -------------------------------------------------------------

    def run_query(self, sql: str, max_rows: int | None = None) -> dict[str, Any]:
        """Run a single SQL statement against Drill and return its rows."""
        try:
            check(sql, self._policy)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc

        limit = self._effective_max_rows(max_rows)
        try:
            result = self._client.query(sql, max_rows=limit)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

        payload: dict[str, Any] = {
            "columns": result.columns,
            "rows": result.rows,
            "query_id": result.query_id,
            "truncated": result.truncated,
        }
        if result.truncated:
            payload["note"] = (
                f"Results were truncated at {limit} rows. "
                "Narrow the query or aggregate to see the rest."
            )
        return payload

    def list_schemas(self) -> list[dict[str, Any]]:
        """List every schema visible on the cluster."""
        try:
            schemas = self._client.schemas()
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
        return [s for s in schemas if self._visible(s.get("name"))]

    def list_tables(self, schema: str) -> list[dict[str, Any]]:
        """List the tables in one schema."""
        self._refuse_if_hidden(schema)
        try:
            return self._client.tables(schema)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

    def describe_table(self, schema: str, table: str) -> list[dict[str, Any]]:
        """List a table's columns with their types and nullability."""
        self._refuse_if_hidden(schema)
        try:
            return self._client.columns(schema, table)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/server.py tests/test_server.py
git commit -m "feat: query and metadata MCP tools"
```

---

### Task 9: Tool layer — management tools and `SHOW` filtering

**Files:**
- Modify: `drill_mcp/server.py`
- Test: `tests/test_server.py` (append)

**Interfaces:**
- Consumes: everything from Task 8
- Produces, all on `DrillTools`: `list_storage_plugins() -> list[dict]`, `cluster_status() -> dict`, `list_profiles(limit: int = 20) -> list[dict]`, `get_profile(query_id: str) -> dict`, `cancel_query(query_id: str) -> str`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_server.py`:

```python
class TestManagementTools:
    def test_list_storage_plugins_passes_through_redacted_output(self):
        client = MagicMock()
        client.storage_plugins.return_value = [
            {"name": "s3", "config": {"secret": "***REDACTED***"}}
        ]
        assert make_tools(client).list_storage_plugins()[0]["name"] == "s3"

    def test_list_storage_plugins_hides_plugins_backing_hidden_schemas(self):
        client = MagicMock()
        client.storage_plugins.return_value = [{"name": "sys"}, {"name": "dfs"}]
        result = make_tools(client, hidden_schemas=["sys"]).list_storage_plugins()
        assert [p["name"] for p in result] == ["dfs"]

    def test_cluster_status(self):
        client = MagicMock()
        client.cluster_status.return_value = {"status": "Running!"}
        assert make_tools(client).cluster_status()["status"] == "Running!"

    def test_list_profiles_uses_the_default_limit(self):
        client = MagicMock()
        client.profiles.return_value = []
        make_tools(client).list_profiles()
        assert client.profiles.call_args.kwargs["limit"] == 20

    def test_list_profiles_honours_an_explicit_limit(self):
        client = MagicMock()
        client.profiles.return_value = []
        make_tools(client).list_profiles(limit=5)
        assert client.profiles.call_args.kwargs["limit"] == 5

    def test_get_profile(self):
        client = MagicMock()
        client.profile.return_value = {"queryId": "abc"}
        assert make_tools(client).get_profile("abc")["queryId"] == "abc"

    def test_cancel_query(self):
        client = MagicMock()
        client.cancel_query.return_value = "Cancelled"
        assert make_tools(client).cancel_query("abc") == "Cancelled"

    def test_management_tools_are_unavailable_on_a_client_without_them(self):
        client = MagicMock(spec=["query", "schemas", "tables", "columns"])
        with pytest.raises(ToolError, match="REST"):
            make_tools(client).cluster_status()

    def test_drill_errors_become_tool_errors(self):
        client = MagicMock()
        client.profile.side_effect = DrillError("no such query")
        with pytest.raises(ToolError, match="no such query"):
            make_tools(client).get_profile("abc")


class TestShowFiltering:
    """SHOW is evaluated server-side by Drill, so rows are filtered on return."""

    def test_show_schemas_rows_are_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_databases_rows_are_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "INFORMATION_SCHEMA"}, {"SCHEMA_NAME": "dfs"}],
        )
        result = make_tools(client, hidden_schemas=["INFORMATION_SCHEMA"]).run_query(
            "SHOW DATABASES"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "dfs"}]

    def test_ordinary_select_rows_are_not_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"], [{"SCHEMA_NAME": "sys"}]
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query(
            "SELECT SCHEMA_NAME FROM dfs.tmp.notes"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "sys"}]

    def test_show_filtering_is_a_no_op_without_hidden_schemas(self):
        client = MagicMock()
        client.query.return_value = QueryResult(["SCHEMA_NAME"], [{"SCHEMA_NAME": "sys"}])
        result = make_tools(client).run_query("SHOW SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "sys"}]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_server.py -k "Management or Show" -v`
Expected: FAIL — `AttributeError: 'DrillTools' object has no attribute 'list_storage_plugins'`

- [ ] **Step 3: Add management tools and `SHOW` filtering**

Add this module-level constant near the top of `drill_mcp/server.py`:

```python
import re

# `SHOW SCHEMAS` / `SHOW DATABASES` are evaluated server-side by Drill, so the
# guard cannot filter them — their rows are filtered on the way back instead.
_SHOW_SCHEMAS = re.compile(r"^\s*SHOW\s+(SCHEMAS|DATABASES)\b", re.IGNORECASE)
```

In `run_query`, filter the rows before building the payload — insert this
immediately after the `self._client.query(...)` call:

```python
        rows = result.rows
        if self._policy.hidden_schemas and _SHOW_SCHEMAS.match(sql):
            rows = [row for row in rows if self._visible(_first_value(row))]
```

and use `rows` in place of `result.rows` in the payload.

Add the helper at module level:

```python
def _first_value(row: dict[str, Any]) -> str | None:
    for value in row.values():
        return str(value) if value is not None else None
    return None
```

Append the management methods to `DrillTools`:

```python
    def _require_management(self, name: str) -> Any:
        method = getattr(self._client, name, None)
        if method is None:
            raise ToolError(
                f"'{name}' needs a REST connection to Drill; the JDBC backend "
                "does not expose management endpoints"
            )
        return method

    def list_storage_plugins(self) -> list[dict[str, Any]]:
        """List storage plugin configurations, with all secrets redacted."""
        try:
            plugins = self._require_management("storage_plugins")()
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
        return [p for p in plugins if self._visible(p.get("name"))]

    def cluster_status(self) -> dict[str, Any]:
        """Report Drillbit membership and overall cluster status."""
        try:
            return self._require_management("cluster_status")()
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

    def list_profiles(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent and running query profiles, newest first."""
        try:
            return self._require_management("profiles")(limit=limit)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

    def get_profile(self, query_id: str) -> dict[str, Any]:
        """Fetch the full profile for one query id."""
        try:
            return self._require_management("profile")(query_id)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

    def cancel_query(self, query_id: str) -> str:
        """Cancel a running query by its query id."""
        try:
            return self._require_management("cancel_query")(query_id)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add drill_mcp/server.py tests/test_server.py
git commit -m "feat: management tools and SHOW SCHEMAS filtering"
```

---

### Task 10: Server wiring, entry point, and documentation

**Files:**
- Modify: `drill_mcp/server.py`
- Create: `README.md`, `drill.example.yaml`
- Test: `tests/test_server.py` (append)

**Interfaces:**
- Consumes: everything above
- Produces:
  - `drill_mcp.server.build_client(config: Config) -> RestClient | JdbcClient`
  - `drill_mcp.server.build_server(config: Config) -> FastMCP`
  - `drill_mcp.server.main(argv: list[str] | None = None) -> int`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_server.py`:

```python
from drill_mcp.client_jdbc import JdbcClient
from drill_mcp.client_rest import RestClient
from drill_mcp.server import build_client, build_server


class TestWiring:
    def test_rest_backend_builds_a_rest_client(self):
        assert isinstance(build_client(load_config()), RestClient)

    def test_jdbc_backend_builds_a_jdbc_client(self):
        cfg = load_config(overrides={"backend": "jdbc", "jdbc_driver_path": "/x.jar"})
        assert isinstance(build_client(cfg), JdbcClient)

    def test_all_nine_tools_are_registered(self):
        server = build_server(load_config())
        names = {tool.name for tool in server._tool_manager.list_tools()}
        assert names == {
            "run_query",
            "list_schemas",
            "list_tables",
            "describe_table",
            "list_storage_plugins",
            "cluster_status",
            "list_profiles",
            "get_profile",
            "cancel_query",
        }

    def test_every_tool_has_a_description(self):
        server = build_server(load_config())
        assert all(tool.description for tool in server._tool_manager.list_tools())

    def test_no_write_or_mutation_tools_are_registered(self):
        server = build_server(load_config())
        names = {tool.name for tool in server._tool_manager.list_tools()}
        forbidden = {"create_storage_plugin", "update_storage_plugin",
                     "delete_storage_plugin", "set_option", "alter_system"}
        assert not (names & forbidden)


class TestMain:
    def test_config_error_exits_nonzero_with_a_message(self, capsys):
        from drill_mcp.server import main

        assert main(["--config", "/nonexistent.yaml"]) == 1
        assert "not found" in capsys.readouterr().err

    def test_cli_flags_reach_the_config(self, monkeypatch):
        from drill_mcp import server as server_module

        captured = {}
        monkeypatch.setattr(
            server_module, "build_server", lambda cfg: captured.setdefault("cfg", cfg) or MagicMock()
        )
        server_module.main(["--url", "http://cli:8047", "--max-rows", "7"])
        assert captured["cfg"].url == "http://cli:8047"
        assert captured["cfg"].max_rows == 7
```

**Note:** `server._tool_manager.list_tools()` reaches into FastMCP internals. If your `mcp` version exposes a public accessor, use it and adjust the test.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_server.py -k "Wiring or Main" -v`
Expected: FAIL — `ImportError: cannot import name 'build_client' from 'drill_mcp.server'`

- [ ] **Step 3: Add wiring and the entry point**

Add to the imports at the top of `drill_mcp/server.py`:

```python
import argparse
import sys

from mcp.server.fastmcp import FastMCP

from .client_rest import RestClient
from .config import ConfigError, load_config
```

Append to `drill_mcp/server.py`:

```python
def build_client(config: Config) -> Any:
    if config.backend == "jdbc":
        from .client_jdbc import JdbcClient

        return JdbcClient(config)
    return RestClient(config)


def build_server(config: Config) -> FastMCP:
    client = build_client(config)
    tools = DrillTools(config, client)
    server = FastMCP("drill")
    for method in (
        tools.run_query,
        tools.list_schemas,
        tools.list_tables,
        tools.describe_table,
        tools.list_storage_plugins,
        tools.cluster_status,
        tools.list_profiles,
        tools.get_profile,
        tools.cancel_query,
    ):
        server.add_tool(method, name=method.__name__, description=method.__doc__)
    return server


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="drill-mcp", description="MCP server for Apache Drill")
    parser.add_argument("--config", help="path to a YAML config file")
    parser.add_argument("--url", help="Drill HTTP endpoint, e.g. http://localhost:8047")
    parser.add_argument("--backend", choices=["rest", "jdbc"])
    parser.add_argument("--auth", choices=["none", "basic", "kerberos"])
    parser.add_argument("--max-rows", type=int, dest="max_rows")
    parser.add_argument(
        "--writable-plugin",
        action="append",
        dest="writable_plugins",
        metavar="PLUGIN",
        help="permit data writes into this plugin; repeatable, empty by default",
    )
    parser.add_argument(
        "--hidden-schema",
        action="append",
        dest="hidden_schemas",
        metavar="SCHEMA",
        help="hide this schema from listings and queries; repeatable",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    overrides = {
        key: value
        for key, value in vars(args).items()
        if key != "config" and value is not None
    }
    try:
        config = load_config(args.config, overrides=overrides)
    except ConfigError as exc:
        print(f"drill-mcp: configuration error: {exc}", file=sys.stderr)
        return 1
    build_server(config).run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Write `drill.example.yaml`**

```yaml
# Apache Drill MCP server configuration.
# Every value below is a default; delete what you do not need to change.

url: http://localhost:8047
backend: rest              # rest | jdbc
auth: none                 # none | basic | kerberos

# Credentials may also come from DRILL_USER / DRILL_PASSWORD.
# user: alice
# password: s3cret

max_rows: 1000
timeout_seconds: 60

# Plugins permitted to accept CTAS / CREATE VIEW / DROP. Empty means no writes.
writable_plugins: []
# writable_plugins: [dfs.tmp]

# Schemas hidden from listings and rejected in queries.
hidden_schemas: []
# hidden_schemas: [sys, INFORMATION_SCHEMA]

# Required when backend is jdbc.
# jdbc_driver_path: /opt/drill/jars/jdbc-driver/drill-jdbc-all.jar
```

- [ ] **Step 6: Write `README.md`**

````markdown
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

## Tools

| Tool | Description |
|---|---|
| `run_query` | Run one SQL statement |
| `list_schemas` | List visible schemas |
| `list_tables` | List tables in a schema |
| `describe_table` | Column names, types, nullability |
| `list_storage_plugins` | Plugin configs, secrets redacted |
| `cluster_status` | Drillbit membership and status |
| `list_profiles` | Recent and running queries |
| `get_profile` | Full profile for one query id |
| `cancel_query` | Cancel a running query |

## Safety model

- **Writes are denied by default.** `CREATE TABLE AS`, `CREATE VIEW`, and `DROP`
  are permitted only into plugins listed in `writable_plugins`. Everything else
  — `INSERT`, `ALTER`, `USE` — is always rejected.
- **`ALTER SYSTEM` and storage plugin editing are not implemented.** There is no
  flag that turns them on.
- **Secrets are always redacted** from storage plugin output.
- **Schemas can be hidden** via `hidden_schemas`, which filters them from
  listings and rejects queries that reference them. Hiding `INFORMATION_SCHEMA`
  does not break the metadata tools, which query it internally.
- Statements are checked with a real SQL parser, so writes hidden in comments,
  string literals, or stacked statements do not slip through.

See `drill.example.yaml` for the full configuration.

## Development

```bash
pip install -e ".[dev]"
pytest                       # unit tests, no cluster or JVM needed
pytest -m integration        # requires a live Drill at DRILL_URL
```
````

- [ ] **Step 7: Run the whole suite with coverage**

Run: `pytest --cov=drill_mcp --cov-report=term-missing`
Expected: PASS. `guard.py` and `redact.py` at 100%; everything else at 90%+.
Add tests for any uncovered branch before committing.

- [ ] **Step 8: Verify the server actually starts**

Run: `drill-mcp --config /nonexistent.yaml`
Expected: exits 1 with `drill-mcp: configuration error: config file not found: /nonexistent.yaml`

Run: `python -c "from drill_mcp.server import build_server; from drill_mcp.config import load_config; print(len(build_server(load_config())._tool_manager.list_tools()))"`
Expected: prints `9`

- [ ] **Step 9: Commit**

```bash
git add drill_mcp/server.py README.md drill.example.yaml tests/test_server.py
git commit -m "feat: server wiring, CLI entry point, and documentation"
```

---

## Verification Checklist

Run before declaring the plan complete:

- [ ] `pytest --cov=drill_mcp --cov-report=term-missing` passes with no failures
- [ ] `guard.py` and `redact.py` at 100% line coverage
- [ ] `grep -ri "alter system\|create_storage\|update_storage\|delete_storage" drill_mcp/` returns nothing outside comments and the README
- [ ] The suite passes with neither `jaydebeapi` nor `JPype1` installed
- [ ] `build_server(load_config())` registers exactly the nine tools listed in Task 10
