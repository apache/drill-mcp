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
