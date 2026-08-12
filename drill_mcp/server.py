#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied.  See the License for the specific
# language governing permissions and limitations under the
# License.
#

"""MCP tool layer.

Tool bodies live on `DrillTools` as plain methods so they can be unit-tested
without standing up an MCP session; `build_server` (Task 9/10) registers the
bound methods with the MCP server (`mcp.server.mcpserver.MCPServer` -- this
package's `mcp` dependency renamed `FastMCP` to `MCPServer` as of mcp 2.0.0;
the internal shape used here, `add_tool`/`_tool_manager.list_tools`/`run`,
is unchanged).
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import TYPE_CHECKING, Any

from mcp.server.mcpserver import MCPServer

from .client_rest import DrillError, RestClient
from .config import Config, ConfigError, load_config
from .guard import Policy, PolicyError, check, is_show_command, matches_prefix
from .redact import redact

if TYPE_CHECKING:
    # Imported only for the type checker: build_client's lazy, in-function
    # import of JdbcClient (see below) is what keeps jaydebeapi/JPype1 out
    # of the import graph for the REST-only, JVM-free default install.
    from .client_jdbc import JdbcClient


class ToolError(Exception):
    """The single error type surfaced to MCP clients. Never carries a traceback."""


def _first_value(row: Any) -> str | None:
    if not isinstance(row, dict):
        return None
    for value in row.values():
        return str(value) if value is not None else None
    return None


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

    def _profile_mentions_hidden_schema(self, profile: dict[str, Any]) -> bool:
        """True if a profile's query text names a hidden schema.

        Profiles are cluster-wide: `list_profiles`/`get_profile` surface
        *other users'* query text, so a hidden schema name can leak out here
        as data even though it was never queryable directly -- the one
        enumeration path the guard and the metadata-tool filtering were
        built to close. A case-insensitive substring match against the
        query text is deliberately coarse (over-filtering a profile whose
        SQL merely mentions a hidden schema's name in a string literal is an
        acceptable false positive; missing one is a leak).
        """
        if not self._policy.hidden_schemas:
            return False
        query_text = str(profile.get("query") or "").lower()
        if not query_text:
            return False
        return any(schema.lower() in query_text for schema in self._policy.hidden_schemas)

    def _visible(self, schema: str | None) -> bool:
        # Fail closed, not open: an item this function cannot identify (no
        # name at all) is filtered out rather than shown by default. Drill
        # never actually returns a null schema/plugin name, but this
        # function's whole job is filtering, so its default on a value it
        # cannot classify must not be "keep it".
        if schema is None:
            return False
        return not matches_prefix(schema, self._policy.hidden_schemas)

    # -- query and metadata tools -------------------------------------------

    def run_query(self, sql: str, max_rows: int | None = None) -> dict[str, Any]:
        """Run a single SQL statement against Drill and return its rows."""
        if not isinstance(sql, str):
            raise ToolError("sql must be a string")
        if max_rows is not None and not isinstance(max_rows, int):
            raise ToolError("max_rows must be an integer")

        try:
            check(sql, self._policy)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc
        except Exception as exc:
            # A parse failure the guard itself did not convert (e.g. an
            # exception type it does not anticipate) must still never reach
            # the caller as a raw traceback. Deliberately no str(exc) here:
            # an unexpected exception's text is exactly what might carry a
            # path or internal detail; `from exc` keeps it for a developer
            # without surfacing it to the model.
            raise ToolError("could not check this SQL against policy; rejecting") from exc

        limit = self._effective_max_rows(max_rows)
        try:
            result = self._client.query(sql, max_rows=limit)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

        # SHOW commands are evaluated server-side by Drill, so the guard
        # cannot filter them by rewriting or rejecting the query; their rows
        # are filtered here on the way back instead. This filters *every*
        # SHOW command's first column, not just SHOW SCHEMAS/DATABASES: there
        # is no reliable way to positively identify which SHOW spelling
        # names a schema (see guard.is_show_command's docstring for the
        # three narrower approaches that each leaked hidden schemas through
        # some spelling). Filtering all SHOW output means SHOW TABLES/SHOW
        # FILES rows are incidentally filtered too — a table or file that
        # happens to be named after a hidden schema gets dropped — which is
        # an acceptable, fail-closed trade-off; a leaked schema is not.
        rows = result.rows
        if self._policy.hidden_schemas and is_show_command(sql):
            rows = [row for row in rows if self._visible(_first_value(row))]

        # Belt-and-suspenders: both backend clients already cap `rows` to
        # `limit`, but this tool method is the last chokepoint before the
        # model sees the data, so the cap is enforced here too rather than
        # trusted from below.
        rows = rows[:limit]

        payload: dict[str, Any] = {
            "columns": result.columns,
            "rows": rows,
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

    # -- management tools ---------------------------------------------------

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
        return [
            p for p in plugins if isinstance(p, dict) and self._visible(p.get("name"))
        ]

    def cluster_status(self) -> dict[str, Any]:
        """Report Drillbit membership and overall cluster status."""
        try:
            return self._require_management("cluster_status")()
        except DrillError as exc:
            raise ToolError(str(exc)) from exc

    def list_profiles(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent and running query profiles, newest first."""
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ToolError("limit must be an integer")
        try:
            profiles = self._require_management("profiles")(limit=limit)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
        profiles = redact(profiles)
        return [
            p
            for p in profiles
            if isinstance(p, dict) and not self._profile_mentions_hidden_schema(p)
        ]

    def get_profile(self, query_id: str) -> dict[str, Any]:
        """Fetch the full profile for one query id."""
        if not isinstance(query_id, str):
            raise ToolError("query_id must be a string")
        try:
            profile = self._require_management("profile")(query_id)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc
        if isinstance(profile, dict) and self._profile_mentions_hidden_schema(profile):
            raise ToolError(f"profile {query_id!r} references a hidden schema")
        return redact(profile)

    def cancel_query(self, query_id: str) -> str:
        """Cancel a running query by its query id."""
        if not isinstance(query_id, str):
            raise ToolError("query_id must be a string")
        try:
            return self._require_management("cancel_query")(query_id)
        except DrillError as exc:
            raise ToolError(str(exc)) from exc


def build_client(config: Config) -> RestClient | JdbcClient:
    """Construct the wire client the configured backend calls for."""
    if config.backend == "jdbc":
        from .client_jdbc import JdbcClient

        return JdbcClient(config)
    return RestClient(config)


def build_server(config: Config) -> MCPServer:
    """Build an MCP server with every read/metadata tool registered.

    No write- or mutation-capable tool is ever registered here: storage
    plugin create/update/delete and `ALTER SYSTEM` have no implementation
    anywhere in this package, so there is nothing such a tool could call.
    """
    client = build_client(config)
    tools = DrillTools(config, client)
    server = MCPServer("drill")
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
    # sqlglot logs a WARNING-level "Falling back to parsing as a 'Command'"
    # message for every SHOW/EXPLAIN/ALTER statement the guard parses.
    # Python's logging module writes unconfigured loggers to stderr, never
    # stdout (verified: `logging.getLogger("sqlglot").warning(...)` with no
    # handler configured lands only on stderr via the last-resort handler),
    # so this cannot corrupt the JSON-RPC session on stdio -- it is only
    # quieted here so operators are not spammed. Configured here, not at
    # import time: a library that reconfigures logging as a side effect of
    # being imported is bad manners.
    logging.getLogger("sqlglot").setLevel(logging.ERROR)

    args = _parse_args(argv)
    overrides = {
        key: value
        for key, value in vars(args).items()
        if key != "config" and value is not None
    }
    try:
        config = load_config(args.config, overrides=overrides)
        build_server(config).run()
    except (ConfigError, DrillError) as exc:
        print(f"drill-mcp: configuration error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
