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
# case-insensitively, with flexible whitespace, since it arrives embedded in
# markup rather than as the whole body.
_INVALID_CREDENTIALS = re.compile(r"invalid\s+username\s*/\s*password\s+credentials", re.IGNORECASE)


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


# -- client --------------------------------------------------------------


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
        if _INVALID_CREDENTIALS.search(response.text):
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
