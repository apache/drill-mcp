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

from contextlib import closing
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


def _type_name(description_entry: tuple) -> str | None:
    """Extract a per-column type name from one `cursor.description` entry.

    `description_entry[1]` is the DB-API `type_code`. jaydebeapi's is
    typically a `DBAPITypeObject`-like value carrying a `.values` tuple of
    type name strings, not a bare string -- stringifying it directly (`str
    (type_code)`) yields an object repr (`<...DBAPITypeObject object at
    0x...>`), not a usable type name. Mirrors sqlalchemy-drill's
    `get_columns` (base.py:433-438), which checks for `.values` the same
    way before falling back to `str()`.
    """
    if len(description_entry) <= 1:
        return None
    type_code = description_entry[1]
    if type_code is None:
        return None
    values = getattr(type_code, "values", None)
    if values:
        return str(values[0])
    return str(type_code)


class JdbcClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._connection: Any = None

    # -- connection --------------------------------------------------------

    def _jdbc_url(self) -> str:
        # Built from hostname/port ONLY -- never `netloc`, which for a URL
        # like "http://alice:s3cret@drill:8047" includes the userinfo
        # ("alice:s3cret@drill:8047"). config.url is free-form and
        # unvalidated, so a password embedded there must never reach the
        # connection string, or it becomes reachable through a driver
        # exception that echoes its arguments back (see _scrub, which
        # handles the remaining case: the driver echoing the password we
        # pass to jaydebeapi.connect() separately, below).
        parsed = urlparse(self._config.url)
        host = parsed.hostname or parsed.path
        netloc = f"{host}:{parsed.port}" if parsed.port else host
        url = f"jdbc:drill:drillbit={netloc}"
        if self._config.auth == "kerberos":
            url += ";auth=kerberos"
        return url

    def _scrub(self, text: str) -> str:
        """Remove the configured password from driver-supplied error text.

        `redact()` in `client_rest.py` doesn't apply here -- it's key-based
        over dicts/lists/tuples and passes a bare `str` through unchanged.
        The driver's exception text is exactly that: a bare string we do not
        control, and it can contain the password we handed to
        `jaydebeapi.connect()` (e.g. an auth-failure message that echoes its
        arguments) or, via the JDBC URL, one a caller embedded in `config.url`
        as userinfo despite `_jdbc_url` no longer forwarding it verbatim.
        """
        password = self._config.password
        if password:
            text = text.replace(password, "***REDACTED***")
        return text

    def _connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import jaydebeapi
        except ImportError as exc:
            raise DrillError(
                "the JDBC backend requires the jdbc extra: pip install drill-mcp[jdbc]"
            ) from exc
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
            raise DrillError(
                f"could not connect to Drill over JDBC: {self._scrub(str(exc))}"
            ) from exc
        return self._connection

    def close(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.close()
        except Exception as exc:
            raise DrillError(
                f"could not close the JDBC connection: {self._scrub(str(exc))}"
            ) from exc
        finally:
            self._connection = None

    # -- queries -------------------------------------------------------------

    def query(self, sql: str, max_rows: int) -> QueryResult:
        connection = self._connect()
        try:
            with closing(connection.cursor()) as cursor:
                cursor.execute(sql)
                rows = cursor.fetchmany(max_rows)
                description = cursor.description or []
                columns = [entry[0] for entry in description]
                metadata = [_type_name(entry) for entry in description]
        except Exception as exc:
            raise DrillError(self._scrub(str(exc))) from exc
        return QueryResult(
            columns=columns,
            # JDBC row tuples are column-aligned by the driver; tolerate a
            # mismatch rather than adding an error path to a reviewed hot loop.
            rows=[dict(zip(columns, row, strict=False)) for row in rows],
            truncated=max_rows > 0 and len(rows) >= max_rows,
            metadata=metadata,
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
