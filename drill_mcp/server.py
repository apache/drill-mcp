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
bound methods with FastMCP.
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
