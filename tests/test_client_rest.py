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

import sys
import types

import httpx
import pytest
import respx

from drill_mcp.client_rest import (
    DrillError,
    RestClient,
    quote_identifier,
    quote_identifier_path,
    quote_literal,
    quote_literal_path,
)
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
        [
            "foo'bar",
            "foo;DROP",
            "foo bar",
            "foo\nbar",
            "",
            "foo\\bar",
            "foo`bar",
            "dfs.tmp",
            "foo\n",  # trailing newline: `$` matches before it under .match(), not under .fullmatch()
        ],
    )
    def test_literal_rejects_dangerous_input(self, bad):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_literal(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "foo'bar",
            "foo;DROP",
            "foo bar",
            "foo\nbar",
            "",
            "..",
            "foo\\bar",
            "foo`bar",
            "dfs.tmp\n",  # trailing newline on the last segment
        ],
    )
    def test_literal_path_rejects_dangerous_input(self, bad):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_literal_path(bad)

    def test_identifier_path_rejects_a_backtick(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_identifier_path("dfs`x")

    def test_identifier_rejects_a_backtick(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_identifier("a`b")

    def test_identifier_rejects_a_bare_dot_dot_segment(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_identifier("..")

    def test_identifier_rejects_a_dot_dot_segment_within_a_longer_name(self):
        with pytest.raises(DrillError, match="invalid identifier"):
            quote_identifier("foo...bar")


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
    def test_not_truncated_when_max_rows_is_zero(self):
        # 0 >= 0 would be a false "truncated" without the max_rows > 0 guard.
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": [], "rows": []})
        )
        assert make_client().query("SELECT 1", max_rows=0).truncated is False

    @respx.mock
    def test_non_json_response_is_reported_as_drill_error(self):
        # A 200 HTML page (e.g. from an SSO gateway or an undetected auth
        # failure in front of Drill) must not surface a bare JSONDecodeError.
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, text="<html><body>not json</body></html>")
        )
        with pytest.raises(DrillError, match="non-JSON"):
            make_client().query("SELECT 1", max_rows=10)

    @respx.mock
    def test_drill_error_text_is_surfaced(self):
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(500, json={"errorMessage": "VALIDATION ERROR: no such table"})
        )
        with pytest.raises(DrillError, match="no such table"):
            make_client().query("SELECT * FROM nope", max_rows=10)

    @respx.mock
    def test_connection_failure_message_names_the_url_not_the_password(self):
        # A real connection failure affects every request to the host, including
        # the basic-auth login that precedes the first query, so both endpoints
        # must fail the same way for this to simulate a real outage.
        respx.post(f"{BASE}/j_security_check").mock(side_effect=httpx.ConnectError("refused"))
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
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        query = respx.post(f"{BASE}/query.json").mock(return_value=httpx.Response(401))
        with pytest.raises(DrillError, match="authentication"):
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        # Without bounded call counts, an unbounded retry loop would hang
        # instead of failing -- these assertions are what actually prove the
        # retry is bounded to exactly one attempt.
        assert login.call_count == 2
        assert query.call_count == 2

    @respx.mock
    def test_login_failure_is_reported(self):
        respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(401))
        with pytest.raises(DrillError, match="authentication"):
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)

    @respx.mock
    def test_login_rejects_200_with_invalid_credentials_body(self):
        """Drill's j_security_check returns HTTP 200 even on a wrong password;
        the failure is only visible in the HTML error page body. This is the
        regression test: without checking the body, a wrong password is
        silently treated as a successful login.

        Deliberately no /query.json mock is registered: if login wrongly
        succeeds, the client proceeds to query() and respx raises
        AllMockedAssertionError instead of DrillError, failing this test.
        That's what makes this test non-vacuous -- do not add a query mock
        here, it would silently hollow out the regression coverage.
        """
        respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Invalid username/password credentials</body></html>",
            )
        )
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_login_rejects_200_with_tags_inside_the_marker_phrase(self):
        """The invalid-credentials marker can arrive with HTML tags inside the
        phrase itself (e.g. a <br> mid-sentence), not just surrounding it.
        Matching against the raw markup would miss this."""
        respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Invalid<br>username/password credentials</body></html>",
            )
        )
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_login_rejects_marker_after_a_stray_unmatched_angle_bracket(self):
        """Regression test: a naive tag-strip regex (`<[^>]+>`) treats any
        '<...>' span as a tag, so a stray unmatched '<' before the marker
        (e.g. '1 < 2' in unrelated error text) makes the substitution eat
        everything up to the next unrelated '>' in the document -- including
        the marker itself -- turning a genuinely failed login into an
        apparent success. Checking the raw body as well as the stripped body
        is what prevents that."""
        respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "<div>Warning: 1 < 2 in the system. "
                    "Invalid username/password credentials</div>"
                ),
            )
        )
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_login_rejects_marker_after_an_unclosed_angle_bracket(self):
        """A stray '<' with no matching '>' anywhere in the body at all."""
        respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(
                200,
                text="value < 5. Invalid username/password credentials",
            )
        )
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_login_rejects_plain_marker_with_no_markup(self):
        respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(200, text="Invalid username/password credentials")
        )
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)

    @respx.mock
    def test_login_succeeds_on_200_with_ordinary_body(self):
        login = respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(200, text="<html><body>Welcome</body></html>")
        )
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": ["a"], "rows": []})
        )
        result = make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert login.called
        assert result.columns == ["a"]

    @respx.mock
    def test_login_succeeds_with_incidental_angle_brackets_in_a_normal_body(self):
        """Fail-closed direction: confirm the union check (raw OR stripped)
        has not made ordinary successful logins start failing just because
        the body happens to contain '<' and '>' characters."""
        login = respx.post(f"{BASE}/j_security_check").mock(
            return_value=httpx.Response(
                200, text="<div>Welcome back. Your balance is < 100 and > 0.</div>"
            )
        )
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": ["a"], "rows": []})
        )
        result = make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert login.called
        assert result.columns == ["a"]

    @respx.mock
    def test_reauth_fails_closed_on_invalid_credentials_not_looping(self):
        """A 401 mid-session triggers one re-login; if that re-login also
        reports invalid credentials, the client must fail closed rather than
        retry the query or loop."""
        login = respx.post(f"{BASE}/j_security_check").mock(
            side_effect=[
                httpx.Response(200, text="<html>Welcome</html>"),
                httpx.Response(
                    200,
                    text="<html>Invalid username/password credentials</html>",
                ),
            ]
        )
        query = respx.post(f"{BASE}/query.json").mock(return_value=httpx.Response(401))
        with pytest.raises(DrillError, match="authentication") as exc:
            make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
        assert "s3cret" not in str(exc.value)
        assert login.call_count == 2
        assert query.call_count == 1

    @respx.mock
    def test_no_login_when_auth_is_none(self):
        login = respx.post(f"{BASE}/j_security_check").mock(return_value=httpx.Response(200))
        respx.post(f"{BASE}/query.json").mock(
            return_value=httpx.Response(200, json={"columns": [], "rows": []})
        )
        make_client().query("SELECT 1", max_rows=1)
        assert not login.called


class TestClose:
    def test_close_closes_the_underlying_http_client(self):
        client = make_client()
        assert client._http.is_closed is False
        client.close()
        assert client._http.is_closed is True


class TestKerberosAuth:
    def test_missing_extra_raises_a_clear_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "httpx_gssapi", None)
        with pytest.raises(DrillError, match=r"drill-mcp\[kerberos\]"):
            make_client(auth="kerberos")

    def test_extra_present_wires_the_auth_object_into_the_http_client(self, monkeypatch):
        class _FakeSpnegoAuth(httpx.Auth):
            def auth_flow(self, request):
                yield request

        sentinel = _FakeSpnegoAuth()
        stub = types.SimpleNamespace(HTTPSPNEGOAuth=lambda: sentinel)
        monkeypatch.setitem(sys.modules, "httpx_gssapi", stub)
        client = make_client(auth="kerberos")
        assert client._http.auth is sentinel


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

    @respx.mock
    def test_plugin_type_returns_the_schema_type(self):
        route = respx.post(f"{BASE}/query.json").mock(
            return_value=query_response(
                ["SCHEMA_NAME", "TYPE"], [{"SCHEMA_NAME": "dfs.tmp", "TYPE": "file"}]
            )
        )
        assert make_client().plugin_type("dfs.tmp") == "file"
        assert b"'dfs.tmp'" in route.calls.last.request.read()


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
        # The filename is ONE identifier, not a further dotted path: it must
        # stay inside a single backtick pair, or Drill reads the extension as
        # the table name and the stem as part of the schema.
        assert b"`sales.csv`" in body
        assert b"`sales`.`csv`" not in body
        # Metadata-only: never read user rows to answer a metadata question.
        assert b"LIMIT 1" not in body
        assert b"SELECT *" not in body

    @respx.mock
    def test_columns_keeps_a_multi_dot_filename_in_one_backtick_pair(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(
                    ["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE"],
                    [{"COLUMN_NAME": "id", "DATA_TYPE": "BIGINT", "IS_NULLABLE": "YES"}],
                ),
            ]
        )
        make_client().columns("dfs.tmp", "archive.2024.json")
        body = route.calls[1].request.read()
        assert b"`archive.2024.json`" in body

    @respx.mock
    def test_columns_works_for_a_file_with_no_extension(self):
        route = respx.post(f"{BASE}/query.json").mock(
            side_effect=[
                self._schemata("file"),
                query_response(
                    ["COLUMN_NAME", "DATA_TYPE", "IS_NULLABLE"],
                    [{"COLUMN_NAME": "id", "DATA_TYPE": "BIGINT", "IS_NULLABLE": "YES"}],
                ),
            ]
        )
        assert make_client().columns("dfs.tmp", "README") == [
            {"name": "id", "data_type": "BIGINT", "nullable": True}
        ]
        assert b"`README`" in route.calls[1].request.read()

    @respx.mock
    def test_columns_table_name_guard_rejects_a_backtick_before_any_query_fires(self):
        # The `_FILE_IDENTIFIER` guard in `fetch_columns` catches this before
        # `plugin_type` (and thus `quote_identifier_path`) is ever reached.
        route = respx.post(f"{BASE}/query.json").mock(return_value=self._schemata("file"))
        with pytest.raises(DrillError, match="invalid identifier"):
            make_client().columns("dfs.tmp", "sales`; DROP TABLE x --.csv")
        assert not route.called

    @respx.mock
    def test_columns_rejects_a_bare_dot_dot_table_name(self):
        route = respx.post(f"{BASE}/query.json").mock(return_value=self._schemata("file"))
        with pytest.raises(DrillError, match="invalid identifier"):
            make_client().columns("dfs.tmp", "..")
        assert not route.called

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
    def test_tables_schema_name_is_rejected_before_the_plugin_type_lookup(self):
        # `plugin_type`'s own `quote_literal_path` call rejects this before
        # `quote_identifier_path` (the SHOW FILES path) is ever reached.
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
    def test_storage_plugins_non_json_response_is_a_drill_error(self):
        # A 200 response carrying HTML -- the auth-proxy scenario `_login`
        # exists to handle -- must not raise a raw JSONDecodeError.
        respx.get(f"{BASE}/storage.json").mock(
            return_value=httpx.Response(200, text="<html>not json</html>")
        )
        with pytest.raises(DrillError, match="non-JSON response"):
            make_client().storage_plugins()

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
    def test_profiles_tolerates_a_non_dict_payload(self):
        respx.get(f"{BASE}/profiles.json").mock(
            return_value=httpx.Response(200, json=["unexpected", "list", "payload"])
        )
        assert make_client().profiles(limit=5) == []

    @respx.mock
    def test_profiles_clamps_a_negative_limit_to_zero(self):
        respx.get(f"{BASE}/profiles.json").mock(
            return_value=httpx.Response(
                200,
                json={"runningQueries": [{"queryId": "live"}], "finishedQueries": []},
            )
        )
        assert make_client().profiles(limit=-5) == []

    @respx.mock
    def test_profiles_non_json_response_is_a_drill_error(self):
        respx.get(f"{BASE}/profiles.json").mock(
            return_value=httpx.Response(200, text="<html>not json</html>")
        )
        with pytest.raises(DrillError, match="non-JSON response"):
            make_client().profiles(limit=5)

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
    def test_profile_non_json_response_is_a_drill_error(self):
        respx.get(f"{BASE}/profiles/abc.json").mock(
            return_value=httpx.Response(200, text="<html>not json</html>")
        )
        with pytest.raises(DrillError, match="non-JSON response"):
            make_client().profile("abc")

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
