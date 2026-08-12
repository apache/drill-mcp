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

"""Drill JDBC backend.

Optional, installed via `pip install drill-mcp[jdbc]`. It exists mainly because
Kerberos is materially less painful through the Drill JDBC driver than through
Python SPNEGO. Query and metadata only -- management endpoints are REST-only,
so `JdbcClient` deliberately does not implement `storage_plugins`,
`cluster_status`, `profiles`, `profile`, or `cancel_query`.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .client_rest import (
    DrillError,
    QueryResult,
    fetch_columns,
    fetch_plugin_type,
    fetch_schemas,
    fetch_tables,
)
from .config import Config

DRIVER_CLASS = "org.apache.drill.jdbc.Driver"


class JdbcClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._connection: Any = None

    # -- connection --------------------------------------------------------

    def _jdbc_url(self) -> str:
        # Credentials are never embedded in the URL -- they are passed to
        # jaydebeapi.connect() as a separate argument (see _connect below) --
        # so this string, and anything derived from it in an error message,
        # cannot leak the password.
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
            # `exc` is whatever the driver reports; it is never supplemented
            # here with the URL or credentials, so this message can only leak
            # a credential if the driver itself already put one in `exc`.
            raise DrillError(f"could not connect to Drill over JDBC: {exc}") from exc
        return self._connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    # -- queries -------------------------------------------------------------

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

    # -- metadata --------------------------------------------------------------
    #
    # Metadata is identical for both backends: it is plain SQL over a `query`
    # callable, including the file-plugin branching. Task 6's implementations
    # were extracted into module-level functions in `client_rest.py` that take
    # a query callable, so both clients delegate to the same functions rather
    # than duplicating the security-relevant identifier quoting.

    def plugin_type(self, schema: str) -> str | None:
        return fetch_plugin_type(self.query, schema)

    def schemas(self) -> list[dict[str, Any]]:
        return fetch_schemas(self.query)

    def tables(self, schema: str) -> list[dict[str, Any]]:
        return fetch_tables(self.query, schema)

    def columns(self, schema: str, table: str) -> list[dict[str, Any]]:
        return fetch_columns(self.query, schema, table)
