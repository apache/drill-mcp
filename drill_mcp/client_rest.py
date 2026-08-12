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
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

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
_IDENTIFIER = re.compile(r"[A-Za-z0-9_$-]+")

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
    # Per-column type strings aligned with `columns`, e.g. "VARCHAR(10)".
    # Drill's REST API returns this in a `metadata` array (Drill >= 1.19);
    # older Drill omits it. Absent metadata is not an error -- callers that
    # need types (e.g. `_probe_columns`) must tolerate an empty list here.
    # `None` entries are deliberate (absent metadata, or padding for a
    # shorter-than-`columns` array), not just an artifact of the default.
    metadata: list[str | None] = field(default_factory=list)


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


def _is_valid_file_identifier(value: str) -> bool:
    """`_FILE_IDENTIFIER` plus a check that no "." segment is empty or "..".

    `_FILE_IDENTIFIER` alone permits a bare ".." (or a leading/trailing/
    doubled dot), which Drill treats as a directory reference -- e.g.
    `columns("dfs.tmp", "..")` would otherwise reach the workspace's parent.
    "/" is excluded from the character class, so this can never traverse more
    than one level or reach a specific file, but it should still be rejected.
    """
    if not _FILE_IDENTIFIER.fullmatch(value):
        return False
    return all(part not in ("", "..") for part in value.split("."))


def quote_identifier(value: str) -> str:
    """Quote a single identifier that may itself contain dots, e.g. a filename.

    `sales.csv` is one identifier, not a two-part path: a dotted filename must
    stay inside a single backtick pair, or Drill reads the extension as the
    table name and the stem as part of the schema (see
    sqlalchemy_drill.base.DrillIdentifierPreparer.format_drill_table, which
    quotes plugin.`workspace`.`file.ext` the same way). Reject rather than
    escape -- same trust boundary as `quote_identifier_path`.
    """
    if not _is_valid_file_identifier(value):
        raise DrillError(f"invalid identifier: {value!r}")
    return f"`{value}`"


_QUERY_ID = re.compile(r"[A-Za-z0-9-]+")


def _check_query_id(query_id: str) -> str:
    if not _QUERY_ID.fullmatch(query_id):
        raise DrillError(f"invalid query id: {query_id!r}")
    return query_id


def _safe_url(url: str) -> str:
    """Return `url` with any embedded userinfo (e.g. a password) stripped.

    `config.url` is free-form and unvalidated, so nothing stops a value like
    `http://alice:s3cret@drill:8047`. Every message that echoes the URL back
    to the model must use this instead of the raw config value -- the
    `client_jdbc.py` backend already applies this exact defense to its
    connection string; the REST backend must not diverge.
    """
    parsed = urlparse(url)
    if not parsed.hostname:
        return url
    netloc = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=netloc))


def _json(response: httpx.Response, url: str) -> Any:
    """Decode a response body as JSON, converting a decode failure to `DrillError`.

    A 200 response carrying HTML -- exactly the auth-proxy scenario `_login`
    exists to handle -- must never raise a raw `json.JSONDecodeError` out of
    the client boundary.
    """
    try:
        return response.json()
    except ValueError as exc:
        raise DrillError(f"Drill at {url} returned a non-JSON response") from exc


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


# -- metadata -----------------------------------------------------------
#
# Pure SQL-building plus row-mapping over a `query` callable -- no transport
# concerns. Extracted to module level (rather than left as RestClient methods)
# so `JdbcClient` can share the exact same identifier-quoting and file-plugin
# branching instead of duplicating ~80 lines of security-relevant logic.

# Called positionally as `query(sql, max_rows)`, not with keyword arguments --
# RestClient.query and JdbcClient.query both accept `max_rows` positionally,
# but a bound method's parameter name is not part of `Callable`'s contract.
Query = Callable[[str, int], QueryResult]


# Plugin types whose schema is discovered at read time rather than registered
# in INFORMATION_SCHEMA. `DESCRIBE` cannot answer for these -- there is
# nothing durable to describe -- so `fetch_columns` must probe with a
# `SELECT ... LIMIT 1` instead. Matches sqlalchemy-drill's `get_columns`
# (base.py:405-470), which is the methodology this module follows rather
# than inventing its own.
DYNAMIC_SCHEMA_TYPES = ("file", "mongo", "splunk")

# Strips size/precision info from a Drill type string, e.g. "VARCHAR(10)" ->
# "VARCHAR", "DECIMAL(10, 2)" -> "DECIMAL". Same approach drilldbapi's
# `Cursor.execute` uses on the `metadata` array (sad.py:278).
_TYPE_PRECISION = re.compile(r"\(.*\)")


def fetch_plugin_type(query: Query, schema: str) -> str | None:
    """Return the storage plugin TYPE backing `schema`, or None if unknown.

    File-based plugins (`dfs`, `s3`) do not register their contents in
    INFORMATION_SCHEMA, so `fetch_tables` and `fetch_columns` must branch on
    this.

    A *bare* plugin name (`dfs`) has no exact SCHEMATA row of its own --
    only its workspaces do (`dfs.tmp`, `dfs.root`). SCHEMATA is fetched once,
    unfiltered, and matched in Python: an exact match wins; otherwise the
    first row whose name's leading dotted component equals `schema` is used.
    This is deliberately NOT a `WHERE SCHEMA_NAME LIKE '%schema%'` clause
    (which is what sqlalchemy-drill's `get_plugin_type` does, base.py:474) --
    `schema` is model-supplied, and `%`/`_` are wildcards in a LIKE pattern.
    """
    quote_literal_path(schema)  # validate the identifier before any query fires
    result = query(
        "SELECT SCHEMA_NAME, TYPE FROM INFORMATION_SCHEMA.`SCHEMATA`",
        10_000,
    )
    prefix_match: str | None = None
    for row in result.rows:
        name = row.get("SCHEMA_NAME")
        if name == schema:
            return row.get("TYPE")
        if prefix_match is None and name and name.split(".", 1)[0] == schema:
            prefix_match = row.get("TYPE")
    return prefix_match


def fetch_schemas(query: Query) -> list[dict[str, Any]]:
    result = query(
        "SELECT SCHEMA_NAME, TYPE FROM INFORMATION_SCHEMA.`SCHEMATA` "
        "ORDER BY SCHEMA_NAME",
        10_000,
    )
    return [
        {"name": row.get("SCHEMA_NAME"), "type": row.get("TYPE")}
        for row in result.rows
    ]


def fetch_tables(query: Query, schema: str) -> list[dict[str, Any]]:
    # File plugins are absent from INFORMATION_SCHEMA.`TABLES`; querying it
    # for `dfs.tmp` returns an empty list that looks like an empty workspace.
    # `SHOW FILES` is the only way to enumerate them. sqlalchemy-drill's
    # get_table_names branches the same way.
    if fetch_plugin_type(query, schema) == "file":
        result = query(f"SHOW FILES FROM {quote_identifier_path(schema)}", 10_000)
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

    result = query(
        "SELECT TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.`TABLES` "
        f"WHERE TABLE_SCHEMA = {quote_literal_path(schema)} ORDER BY TABLE_NAME",
        10_000,
    )
    return [
        {"name": row.get("TABLE_NAME"), "type": row.get("TABLE_TYPE")}
        for row in result.rows
    ]


def _probe_target(schema: str, table: str) -> str:
    """Quote `schema`.`table` the same way `_describe_columns` does.

    `schema` is a dotted path (each segment quoted individually via
    `quote_identifier_path`); `table` stays inside ONE backtick pair via
    `quote_identifier` because file-plugin table names are filenames that
    may themselves contain a "." (e.g. "sales.csv") -- see `quote_identifier`.

    sqlalchemy-drill's dialect instead special-cases a view's target by
    counting dots in `schema + "." + table` to decide where the
    plugin/workspace/filename boundaries fall (`format_drill_table`,
    base.py:164-193): that heuristic assumes the trailing dotted token is a
    file extension, so for `schema="dfs"`, `table="a.b"` it emits
    ``dfs.a.`b` `` -- splitting a view name that happens to contain a dot in
    two. The dialect's separate view branch in `get_columns`
    (base.py:423-428) exists only to dodge that bug by wrapping the whole
    schema string in a single backtick pair instead. `_probe_target` has no
    such failure mode -- it quotes every schema segment and the
    table/filename correctly and uniformly regardless of whether `table`
    names a view or a file -- so there is no input on which the two
    approaches disagree, and no second quoting scheme or view lookup is
    needed here.
    """
    return f"{quote_identifier_path(schema)}.{quote_identifier(table)}"


def _columns_from_metadata(columns: list[str], metadata: list[str | None]) -> list[dict[str, Any]]:
    """Build `describe_table` rows from a probe's `columns`/`metadata`.

    Never reads `result.rows` -- the caller passes only `columns` and
    `metadata`, so a sampled row value cannot reach this function let alone
    its return value. Nullability is unknowable from a single probed row
    (a `NULL` here says nothing about whether the column CAN be null, and a
    non-`NULL` value says nothing about whether it must); reporting `None`
    is honest, guessing `True` or `False` is not.
    """
    # `zip` silently truncates to the shorter list; pad rather than let a
    # metadata array that is present but short (a malformed or unexpected
    # response) drop trailing columns.
    types = list(metadata) + [None] * max(0, len(columns) - len(metadata))
    result = []
    for name, type_str in zip(columns, types):
        data_type = _TYPE_PRECISION.sub("", type_str) if type_str else None
        result.append({"name": name, "data_type": data_type, "nullable": None})
    return result


def _probe_columns(query: Query, schema: str, table: str, plugin_type: str) -> list[dict[str, Any]]:
    """Discover columns for a dynamic-schema plugin by probing one row.

    `DESCRIBE` cannot answer for `file`/`mongo`/`splunk`: their schema is
    discovered at read time, not registered anywhere `DESCRIBE` can consult.
    Mirrors sqlalchemy-drill's `get_columns` (base.py:405-451).

    Privacy: this reads one row from the underlying data, but only
    `result.columns` and `result.metadata` are used below -- `result.rows`
    is discarded unread. That is what makes the probe acceptable here: the
    caller (`describe_table`) gets column names and types, never sampled
    values.

    A probe FAILURE is left to propagate unchanged, exactly like
    `_describe_columns` and `fetch_plugin_type`: Drill's error text (a
    missing table, a permissions failure, a genuine data error) is what a
    caller needs to tell those apart and correct the request. Confirmed with
    the Drill maintainer that Drill's own errors do not embed cell content,
    so there is nothing here for a probe-specific failure path to guard
    against.
    """
    if plugin_type == "mongo":
        # MongoDB collection names CAN contain dots (e.g. "logs.2024"); this
        # is not special-cased, so such a name is quoted the same as any
        # other dotted path -- one backtick pair per "." segment, exactly
        # like a schema path. sqlalchemy-drill's dialect does the same
        # (base.py:420-422), so this is not a regression, just a limitation
        # shared with the reference: a dotted collection name resolves to a
        # nested path rather than one opaque identifier.
        target = quote_identifier_path(f"{schema}.{table}")
        sql = f"SELECT `**` FROM {target} LIMIT 1"
    else:
        target = _probe_target(schema, table)
        sql = f"SELECT * FROM {target} LIMIT 1"

    result = query(sql, 1)

    if not result.columns:
        # A dynamic-schema plugin discovers columns only by reading data;
        # zero rows means Drill never had anything to infer a schema from.
        # Returning [] here would read exactly like the "no columns" failure
        # mode Step 2 rejects for HTTP plugins -- fail loudly instead.
        raise DrillError(
            f"columns could not be determined for `{schema}`.`{table}` because "
            "the probe returned no rows; the table may be empty."
        )

    return _columns_from_metadata(result.columns, result.metadata)


def _describe_columns(query: Query, schema: str, table: str) -> list[dict[str, Any]]:
    """Discover columns via `DESCRIBE`, for any plugin with a registered schema.

    Mirrors sqlalchemy-drill's `get_columns` `else` branch (base.py:453-472):
    `DESCRIBE` is metadata-only and never reads user data, so it is
    preferred whenever it can answer -- i.e. for anything NOT in
    `DYNAMIC_SCHEMA_TYPES`.
    """
    target = _probe_target(schema, table)
    result = query(f"DESCRIBE {target}", 10_000)
    return [
        {
            "name": row.get("COLUMN_NAME"),
            "data_type": row.get("DATA_TYPE"),
            "nullable": str(row.get("IS_NULLABLE", "")).upper() == "YES",
        }
        for row in result.rows
    ]


def fetch_columns(query: Query, schema: str, table: str) -> list[dict[str, Any]]:
    # Validate the table name up front, before the plugin_type lookup fires
    # a query: an invalid table name should never make it to the network.
    # `_FILE_IDENTIFIER` (not `_IDENTIFIER`) because file-plugin table
    # names are filenames and may contain a literal "." (e.g. "sales.csv")
    # as ONE identifier -- see `quote_identifier`.
    if not _is_valid_file_identifier(table):
        raise DrillError(f"invalid identifier: {table!r}")

    plugin_type = fetch_plugin_type(query, schema)

    # An HTTP plugin has no column metadata until a query has actually been
    # run against the endpoint -- there is no schema to DESCRIBE and no
    # table to probe. Returning [] here would read as "this table has no
    # columns"; fail loudly and explain instead. `schema`/`table` are
    # already known to be valid identifiers at this point (checked above and
    # by `fetch_plugin_type`'s `quote_literal_path` call), so they are safe
    # to embed directly in the message.
    if plugin_type == "http":
        raise DrillError(
            f"Drill cannot report columns for the HTTP plugin schema '{schema}' until a query "
            "has been run against it. Run a query such as\n"
            f"  SELECT * FROM `{schema}`.`{table}` LIMIT 10\n"
            "and read the column names from the result."
        )

    if plugin_type in DYNAMIC_SCHEMA_TYPES:
        return _probe_columns(query, schema, table, plugin_type)

    return _describe_columns(query, schema, table)


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
                f"authentication endpoint at {_safe_url(self._config.url)} returned "
                f"HTTP {response.status_code}"
            )
        if _contains_invalid_credentials_marker(response.text):
            raise DrillError(
                f"authentication failed for user {self._config.user!r} at {_safe_url(self._config.url)}"
            )
        self._authenticated = True

    def _transport_error(self, exc: httpx.HTTPError) -> DrillError:
        if isinstance(exc, httpx.TimeoutException):
            return DrillError(
                f"request to {_safe_url(self._config.url)} timed out after "
                f"{self._config.timeout_seconds}s"
            )
        return DrillError(
            f"could not reach Drill at {_safe_url(self._config.url)} "
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
                f"authentication rejected by Drill at {_safe_url(self._config.url)} "
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
        payload = _json(response, _safe_url(self._config.url))
        rows = payload.get("rows") or []
        truncated = max_rows > 0 and len(rows) >= max_rows
        # Defense in depth: `autoLimit` asks Drill to cap rows server-side,
        # but the cap must not depend entirely on Drill honoring that field.
        # Slice client-side too, exactly like `JdbcClient.query`'s
        # `fetchmany(max_rows)` -- the two backends must agree on this.
        if max_rows > 0:
            rows = rows[:max_rows]
        return QueryResult(
            columns=payload.get("columns") or [],
            rows=rows,
            query_id=payload.get("queryId"),
            truncated=truncated,
            metadata=payload.get("metadata") or [],
        )

    # -- metadata ----------------------------------------------------------

    def schemas(self) -> list[dict[str, Any]]:
        return fetch_schemas(self.query)

    def plugin_type(self, schema: str) -> str | None:
        """Return the storage plugin TYPE backing `schema`, or None if unknown.

        File-based plugins (`dfs`, `s3`) do not register their contents in
        INFORMATION_SCHEMA, so `tables` and `columns` must branch on this.
        """
        return fetch_plugin_type(self.query, schema)

    def tables(self, schema: str) -> list[dict[str, Any]]:
        return fetch_tables(self.query, schema)

    def columns(self, schema: str, table: str) -> list[dict[str, Any]]:
        return fetch_columns(self.query, schema, table)

    # -- management --------------------------------------------------------

    def storage_plugins(self) -> list[dict[str, Any]]:
        response = self._request("GET", "/storage.json")
        return redact(_json(response, _safe_url(self._config.url)))

    def cluster_status(self) -> dict[str, Any]:
        cluster = _json(self._request("GET", "/cluster.json"), _safe_url(self._config.url))
        status = _json(self._request("GET", "/status.json"), _safe_url(self._config.url))
        merged = dict(cluster) if isinstance(cluster, dict) else {"cluster": cluster}
        if isinstance(status, dict):
            merged.update(status)
        else:
            merged["status"] = status
        return merged

    def profiles(self, limit: int) -> list[dict[str, Any]]:
        limit = max(limit, 0)
        response = self._request("GET", "/profiles.json")
        payload = _json(response, _safe_url(self._config.url))
        if not isinstance(payload, dict):
            payload = {}
        running = payload.get("runningQueries") or []
        finished = payload.get("finishedQueries") or []
        return (list(running) + list(finished))[:limit]

    def profile(self, query_id: str) -> dict[str, Any]:
        _check_query_id(query_id)
        response = self._request("GET", f"/profiles/{query_id}.json")
        return _json(response, _safe_url(self._config.url))

    def cancel_query(self, query_id: str) -> str:
        _check_query_id(query_id)
        return self._request("GET", f"/profiles/cancel/{query_id}").text
