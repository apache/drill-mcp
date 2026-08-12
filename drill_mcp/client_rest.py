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

"""Drill REST backend.

Talks to a Drillbit's HTTP endpoints. Metadata methods (Task 6) issue
INFORMATION_SCHEMA queries directly and deliberately bypass `guard.py` — the
guard governs SQL that originated from the model, not SQL this module composes
itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from .config import Config
from .redact import redact

# -- quoting -----------------------------------------------------------------
#
# Trust boundary: schema and table names arrive from the model and are
# interpolated into query strings (Drill's REST API has no bind parameters).
# `_IDENTIFIER` must reject anything that could break out of the surrounding
# single quotes or change SQL structure: no quotes, backslashes, semicolons,
# whitespace, or empty segments. `+` requires at least one character, so the
# empty string never matches, and `quote_literal_path` splits on "." and
# validates every segment, so a lone "." (which splits into two empty
# segments) is rejected too.
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_$-]+$")

# Drill's j_security_check returns HTTP 200 even on a wrong password; the only
# signal is this marker string inside the HTML error page body. Matched
# case-insensitively, with flexible whitespace.
_INVALID_CREDENTIALS = re.compile(r"invalid\s+username\s*/\s*password\s+credentials", re.IGNORECASE)

# Approximates real tag grammar (requires '/', a letter, or '!' after '<') so
# a stray unmatched '<' -- e.g. "1 < 2" in unrelated page text -- can't be
# mistaken for the start of a tag and swallow everything up to the next
# unrelated '>' in the document, potentially deleting the marker itself.
_HTML_TAG = re.compile(r"</?[A-Za-z!][^>]*>")


def _strip_tags(html: str) -> str:
    return _HTML_TAG.sub(" ", html)


def _contains_invalid_credentials_marker(body: str) -> bool:
    """True if `body` contains Drill's invalid-credentials marker.

    Checks the raw body AND the tag-stripped body, and treats a match in
    EITHER as a failure. Stripping is needed to catch the marker when tags
    fall inside the phrase (e.g. "Invalid<br>username/password credentials"),
    but stripping can never be trusted alone: a tag-stripping regex can only
    approximate real HTML grammar, and any case where it over-strips (turning
    unrelated text into something that looks like a tag) would delete the
    marker and silently accept a failed login as successful. Checking the raw
    body first means no stripping bug can ever suppress a detection the raw
    search would have made on its own -- the union can only find more than
    either check alone, never less. This is the correct posture for a check
    that gates authentication: fail closed, not fail clever.
    """
    return bool(_INVALID_CREDENTIALS.search(body) or _INVALID_CREDENTIALS.search(_strip_tags(body)))


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
    if not _IDENTIFIER.fullmatch(value):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"'{value}'"


def quote_literal_path(value: str) -> str:
    """Same as `quote_literal`, but permits a dotted schema path like `dfs.tmp`."""
    parts = value.split(".")
    if any(not _IDENTIFIER.fullmatch(part) for part in parts):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"'{value}'"


def quote_identifier_path(value: str) -> str:
    """Validate a dotted path and return it backtick-quoted: dfs.tmp -> `dfs`.`tmp`.

    Same trust boundary as quote_literal_path -- these values arrive from the
    model and are interpolated into SQL. Reject rather than escape.
    """
    parts = value.split(".")
    if any(not _IDENTIFIER.fullmatch(part) for part in parts):
        raise DrillError(f"invalid identifier: {value!r}")
    return ".".join(f"`{part}`" for part in parts)


# `_IDENTIFIER` plus a literal ".", for filenames like "sales.csv" that are ONE
# identifier, not a dotted path -- see `quote_identifier`. Still excludes
# backticks: a backtick in the value would break out of the quoting below,
# which is the entire trust boundary this regex exists to enforce.
_FILE_IDENTIFIER = re.compile(r"[A-Za-z0-9_$.-]+")


def quote_identifier(value: str) -> str:
    """Quote a single identifier that may itself contain dots, e.g. a filename.

    `sales.csv` is one identifier, not a two-part path: a dotted filename must
    stay inside a single backtick pair, or Drill reads the extension as the
    table name and the stem as part of the schema (see
    sqlalchemy_drill.base.DrillIdentifierPreparer.format_drill_table, which
    quotes plugin.`workspace`.`file.ext` the same way). Reject rather than
    escape -- same trust boundary as `quote_identifier_path`.
    """
    if not _FILE_IDENTIFIER.fullmatch(value):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"`{value}`"


_QUERY_ID = re.compile(r"[A-Za-z0-9-]+")


def _check_query_id(query_id: str) -> str:
    if not _QUERY_ID.fullmatch(query_id):
        raise DrillError(f"invalid query id: {query_id!r}")
    return query_id


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


# -- client --------------------------------------------------------------


class RestClient:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._authenticated = False
        auth = None
        if config.auth == "kerberos":
            try:
                from httpx_gssapi import HTTPSPNEGOAuth
            except ImportError as exc:
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
        # Drill's j_security_check endpoint (standard Java EE FORM auth) returns
        # HTTP 200 with an HTML error page in the body when credentials are
        # wrong -- it does NOT use a 4xx status for a bad password. So status
        # code alone cannot detect an authentication failure; a non-2xx here
        # means the endpoint itself is unreachable/misbehaving (a connection
        # problem), while a wrong password must be detected from the body.
        # (Checking the response URL, as an earlier draft did, is also wrong:
        # an unredirected *successful* login's URL still points at
        # "/j_security_check", so that check false-positives on success.)
        if response.status_code >= 400:
            raise DrillError(
                f"authentication endpoint at {self._config.url} returned "
                f"HTTP {response.status_code}"
            )
        if _contains_invalid_credentials_marker(response.text):
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
        try:
            payload = response.json()
        except ValueError as exc:
            raise DrillError(
                f"Drill at {self._config.url} returned a non-JSON response"
            ) from exc
        rows = payload.get("rows") or []
        return QueryResult(
            columns=payload.get("columns") or [],
            rows=rows,
            query_id=payload.get("queryId"),
            truncated=max_rows > 0 and len(rows) >= max_rows,
        )

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
        # Validate the table name up front, before the plugin_type lookup fires
        # a query: an invalid table name should never make it to the network.
        # `_FILE_IDENTIFIER` (not `_IDENTIFIER`) because file-plugin table
        # names are filenames and may contain a literal "." (e.g. "sales.csv")
        # as ONE identifier -- see `quote_identifier`.
        if not _FILE_IDENTIFIER.fullmatch(table):
            raise DrillError(f"invalid identifier: {table!r}")

        # Same split: file plugins have dynamic schemas and no
        # INFORMATION_SCHEMA.`COLUMNS` rows. DESCRIBE is metadata-only --
        # deliberately NOT a `SELECT * ... LIMIT 1` probe, which would read user
        # data to answer a metadata question.
        if self.plugin_type(schema) == "file":
            # `table` is ONE identifier (a filename), not a further dotted
            # path -- quote it with `quote_identifier`, not
            # `quote_identifier_path`, or "sales.csv" would be split into a
            # schema segment "sales" and a table segment "csv".
            target = f"{quote_identifier_path(schema)}.{quote_identifier(table)}"
            result = self.query(f"DESCRIBE {target}", max_rows=10_000)
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
