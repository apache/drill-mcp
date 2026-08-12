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

from unittest.mock import MagicMock

import pytest

from drill_mcp.client_jdbc import JdbcClient
from drill_mcp.client_rest import DrillError, QueryResult, RestClient
from drill_mcp.config import load_config
from drill_mcp.server import DrillTools, ToolError, build_client, build_server


def make_tools(client=None, **overrides):
    client = client or MagicMock()
    return DrillTools(load_config(overrides=overrides, env={}), client)


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

    def test_enforces_the_row_cap_even_if_the_client_returns_more(self):
        # RestClient and JdbcClient both cap rows themselves, but run_query
        # is the last chokepoint before the model, so it must not simply
        # trust whatever the client hands back.
        client = MagicMock()
        client.query.return_value = QueryResult(["a"], [{"a": i} for i in range(10)], "q1", False)
        result = make_tools(client, max_rows=3).run_query("SELECT 1")
        assert len(result["rows"]) == 3
        assert result["rows"] == [{"a": 0}, {"a": 1}, {"a": 2}]

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

    def test_pathological_sql_that_crashes_the_parser_is_rejected_without_a_traceback(self):
        client = MagicMock()
        deeply_nested = "SELECT " + "(" * 400 + "1" + ")" * 400
        with pytest.raises(ToolError) as excinfo:
            make_tools(client).run_query(deeply_nested)
        client.query.assert_not_called()
        message = str(excinfo.value)
        assert "/" not in message
        assert "\\" not in message
        assert ".py" not in message

    def test_non_string_sql_is_rejected_as_a_tool_error(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="sql must be a string"):
            make_tools(client).run_query(5)
        client.query.assert_not_called()

    def test_non_integer_max_rows_is_rejected_as_a_tool_error(self):
        client = MagicMock()
        with pytest.raises(ToolError, match="max_rows must be an integer"):
            make_tools(client).run_query("SELECT 1", max_rows="10")
        client.query.assert_not_called()


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
        client.tables.assert_called_once_with("dfs.tmp")

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
        client.columns.assert_called_once_with("dfs.tmp", "t")

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

    def test_get_profile_redacts_secret_looking_keys(self):
        # Profiles are cluster-wide: a full profile embeds Drill's
        # serialized physical plan, which for JDBC/HTTP plugins can carry
        # plugin configuration (passwords, tokens). This must go through the
        # same redaction as list_storage_plugins, not be returned unmodified.
        client = MagicMock()
        client.profile.return_value = {"queryId": "abc", "password": "hunter2"}
        result = make_tools(client).get_profile("abc")
        assert result["password"] == "***REDACTED***"
        assert result["queryId"] == "abc"

    def test_get_profile_is_refused_when_its_query_text_names_a_hidden_schema(self):
        # A profile carries the query TEXT of whatever user ran it -- other
        # users' queries, not just the caller's own. A hidden schema's name
        # can leak out here as data even though it is unreachable directly,
        # which is exactly the enumeration path the guard and hidden-schema
        # filtering elsewhere were built to close.
        client = MagicMock()
        client.profile.return_value = {"queryId": "abc", "query": "SELECT * FROM sys.options"}
        with pytest.raises(ToolError, match="hidden"):
            make_tools(client, hidden_schemas=["sys"]).get_profile("abc")

    def test_list_profiles_redacts_secret_looking_keys(self):
        client = MagicMock()
        client.profiles.return_value = [{"queryId": "abc", "password": "hunter2"}]
        result = make_tools(client).list_profiles()
        assert result[0]["password"] == "***REDACTED***"

    def test_list_profiles_drops_entries_whose_query_text_names_a_hidden_schema(self):
        client = MagicMock()
        client.profiles.return_value = [
            {"queryId": "abc", "query": "SELECT * FROM sys.options"},
            {"queryId": "def", "query": "SELECT * FROM dfs.tmp.x"},
        ]
        result = make_tools(client, hidden_schemas=["sys"]).list_profiles()
        assert [p["queryId"] for p in result] == ["def"]

    def test_cancel_query(self):
        client = MagicMock()
        client.cancel_query.return_value = "Cancelled"
        assert make_tools(client).cancel_query("abc") == "Cancelled"

    def test_management_tools_are_unavailable_on_a_client_without_them(self):
        client = MagicMock(spec=["query", "schemas", "tables", "columns"])
        with pytest.raises(ToolError, match="REST"):
            make_tools(client).cluster_status()

    @pytest.mark.parametrize(
        "call",
        [
            lambda tools: tools.list_storage_plugins(),
            lambda tools: tools.cluster_status(),
            lambda tools: tools.list_profiles(),
            lambda tools: tools.get_profile("abc"),
            lambda tools: tools.cancel_query("abc"),
        ],
        ids=[
            "list_storage_plugins",
            "cluster_status",
            "list_profiles",
            "get_profile",
            "cancel_query",
        ],
    )
    def test_every_management_tool_is_unavailable_on_a_client_without_it(self, call):
        # get_profile/cancel_query run their own isinstance validation on
        # query_id before touching the client, so a valid string argument is
        # used here to make sure that validation doesn't mask the missing
        # REST endpoint being detected first.
        client = MagicMock(spec=["query", "schemas", "tables", "columns"])
        with pytest.raises(ToolError, match="REST"):
            call(make_tools(client))

    def test_list_storage_plugins_skips_non_dict_entries_rather_than_crashing(self):
        client = MagicMock()
        client.storage_plugins.return_value = ["not-a-dict", {"name": "dfs"}]
        result = make_tools(client).list_storage_plugins()
        assert [p["name"] for p in result] == ["dfs"]

    def test_drill_errors_become_tool_errors(self):
        client = MagicMock()
        client.profile.side_effect = DrillError("no such query")
        with pytest.raises(ToolError, match="no such query"):
            make_tools(client).get_profile("abc")

    def test_get_profile_rejects_non_string_query_id(self):
        client = MagicMock()
        with pytest.raises(ToolError):
            make_tools(client).get_profile(123)

    def test_cancel_query_rejects_non_string_query_id(self):
        client = MagicMock()
        with pytest.raises(ToolError):
            make_tools(client).cancel_query(123)

    def test_list_profiles_rejects_non_integer_limit(self):
        client = MagicMock()
        with pytest.raises(ToolError):
            make_tools(client).list_profiles(limit="20")


class TestShowFiltering:
    """SHOW is evaluated server-side by Drill, so rows are filtered on return.

    Filtering applies to *every* SHOW command's first column, not just SHOW
    SCHEMAS/SHOW DATABASES. Three narrower attempts at recognising only the
    schema-listing spellings (a raw regex over the SQL text, exact equality
    against the parsed Command's literal, a comment-stripping regex over that
    literal) each leaked hidden schemas through some spelling the classifier
    failed to recognise. Filtering all SHOW output instead means SHOW
    TABLES/SHOW FILES rows are incidentally filtered too, but that direction
    of failure — over-filtering a table that happens to share a name with a
    hidden schema — is the safe one; leaking the schema list is not. See
    guard.is_show_command's docstring for the full history.
    """

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
        client.query.return_value = QueryResult(["SCHEMA_NAME"], [{"SCHEMA_NAME": "sys"}])
        result = make_tools(client, hidden_schemas=["sys"]).run_query(
            "SELECT SCHEMA_NAME FROM dfs.tmp.notes"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "sys"}]

    def test_show_filtering_is_a_no_op_without_hidden_schemas(self):
        client = MagicMock()
        client.query.return_value = QueryResult(["SCHEMA_NAME"], [{"SCHEMA_NAME": "sys"}])
        result = make_tools(client).run_query("SHOW SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "sys"}]

    def test_show_schemas_with_leading_block_comment_is_still_filtered(self):
        """Regression test for the raw-regex bypass: a leading comment defeats
        a `^\\s*SHOW` anchor but not the parser, since the tokenizer strips
        comments before the guard or this filter ever sees the text."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("/* x */ SHOW SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_databases_with_leading_line_comment_is_still_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "INFORMATION_SCHEMA"}, {"SCHEMA_NAME": "dfs"}],
        )
        result = make_tools(client, hidden_schemas=["INFORMATION_SCHEMA"]).run_query(
            "-- comment\nSHOW DATABASES"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "dfs"}]

    def test_show_filtering_is_case_insensitive_lowercase(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("show schemas")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_filtering_is_case_insensitive_mixed_case(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("ShOw ScHeMaS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_tables_rows_are_now_filtered_too(self):
        """Inverted deliberately: SHOW TABLES rows are table names, not
        schema names, so filtering them against hidden_schemas can drop a
        table that happens to share a name with a hidden schema. That is the
        accepted, fail-closed trade-off — SHOW output is filtered as a whole
        because no reliable way exists to single out just the
        schema-listing spellings of SHOW without risking a leak (see the
        class docstring). A table literally named "sys" is rare; a leaked
        hidden schema list is not an acceptable alternative."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["TABLE_NAME"], [{"TABLE_NAME": "sys"}, {"TABLE_NAME": "orders"}]
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW TABLES")
        assert result["rows"] == [{"TABLE_NAME": "orders"}]

    def test_show_tables_like_rows_are_filtered_too(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["TABLE_NAME"], [{"TABLE_NAME": "sys"}, {"TABLE_NAME": "orders"}]
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW TABLES LIKE '%s%'")
        assert result["rows"] == [{"TABLE_NAME": "orders"}]

    def test_show_schemas_like_rows_are_filtered(self):
        """Regression test: `SHOW SCHEMAS LIKE '...'` is documented Drill
        syntax. sqlglot's Command fallback swallows the whole remainder
        (`SCHEMAS LIKE '%dfs%'`) into a single literal, so any classifier
        that inspects that text specifically has some spelling it misses;
        filtering every SHOW command sidesteps the classification problem
        entirely."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW SCHEMAS LIKE '%s%'")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_databases_like_rows_are_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "INFORMATION_SCHEMA"}, {"SCHEMA_NAME": "dfs"}],
        )
        result = make_tools(client, hidden_schemas=["INFORMATION_SCHEMA"]).run_query(
            "SHOW DATABASES LIKE '%y%'"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "dfs"}]

    def test_show_schemas_with_trailing_block_comment_is_still_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW SCHEMAS /* trailing */")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_schemas_with_no_whitespace_before_comment_is_still_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW/**/SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_schemas_with_trailing_semicolon_is_still_filtered(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW SCHEMAS;")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_schemas_with_nested_block_comment_is_still_filtered(self):
        """Regression test for the specific input that defeated the
        comment-stripping regex fix: non-greedy `/\\*.*?\\*/` matching stops
        at the first `*/`, leaving `*/ SCHEMAS` behind, so the "first token"
        became `*/` instead of `SCHEMAS` and the row leaked."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query(
            "SHOW /* /* nested */ */ SCHEMAS"
        )
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_schemas_with_unbalanced_comment_delimiter_is_still_filtered(self):
        """Regression test for the other input that defeated the
        comment-stripping regex: a stray `*/` with no opener strips nothing
        at all, so the row leaked."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW */ SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_row_that_is_not_a_dict_does_not_crash_filtering(self):
        """A malformed row must not raise a raw AttributeError out of the
        filter; it should simply be treated as not identifiable and dropped
        rather than crashing the whole call."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"], ["not-a-dict", {"SCHEMA_NAME": "dfs.tmp"}]
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW SCHEMAS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    @pytest.mark.parametrize(
        "sql",
        [
            "SHOW SCHEMAS",
            "SHOW DATABASES",
            "/* x */ SHOW SCHEMAS",
            "-- c\nSHOW DATABASES",
            "SHOW SCHEMAS LIKE '%dfs%'",
            "SHOW SCHEMAS /* t */",
            "SHOW/**/SCHEMAS",
            "SHOW /* /* nested */ */ SCHEMAS",
            "SHOW */ SCHEMAS",
            "show schemas",
            "SHOW SCHEMAS;",
        ],
    )
    def test_hidden_row_never_appears_in_the_tool_payload(self, sql):
        """End-to-end assertion on the tool's actual output, independent of
        how detection is implemented: for every spelling that previously
        leaked through one of the three narrower classifiers, the hidden
        schema must not appear anywhere in the returned payload, not just in
        a specific `rows` shape."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query(sql)
        assert {"SCHEMA_NAME": "sys"} not in result["rows"]
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]


class TestWiring:
    def test_rest_backend_builds_a_rest_client(self):
        assert isinstance(build_client(load_config(env={})), RestClient)

    def test_jdbc_backend_builds_a_jdbc_client(self):
        cfg = load_config(overrides={"backend": "jdbc", "jdbc_driver_path": "/x.jar"}, env={})
        assert isinstance(build_client(cfg), JdbcClient)

    def test_all_tools_are_registered(self):
        server = build_server(load_config(env={}))
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
        server = build_server(load_config(env={}))
        assert all(tool.description for tool in server._tool_manager.list_tools())

    def test_no_write_or_mutation_tools_are_registered(self):
        server = build_server(load_config(env={}))
        names = {tool.name for tool in server._tool_manager.list_tools()}
        forbidden = {
            "create_storage_plugin",
            "update_storage_plugin",
            "delete_storage_plugin",
            "set_option",
            "alter_system",
        }
        assert not (names & forbidden)

    def test_no_registered_tool_accepts_a_credential_argument(self):
        """Credentials come from config or environment only, never a tool argument."""
        server = build_server(load_config(env={}))
        credential_words = {"user", "password", "username", "passwd", "secret", "token", "credential"}
        for tool in server._tool_manager.list_tools():
            params = set(tool.parameters.get("properties", {}))
            assert not (params & credential_words), (
                f"{tool.name} accepts {params & credential_words}"
            )


class TestMain:
    def test_config_error_exits_nonzero_with_a_message(self, capsys):
        from drill_mcp.server import main

        assert main(["--config", "/nonexistent.yaml"]) == 1
        assert "not found" in capsys.readouterr().err

    def test_cli_flags_reach_the_config(self, monkeypatch):
        from drill_mcp import server as server_module

        # Note: `captured.setdefault("cfg", cfg) or MagicMock()` (as drafted
        # in the task brief) returns the truthy `cfg` itself rather than the
        # MagicMock, so `build_server(cfg).run()` would blow up calling
        # `.run()` on a `Config`. Using a real fake avoids that trap.
        captured = {}

        def fake_build_server(cfg):
            captured["cfg"] = cfg
            return MagicMock()

        monkeypatch.setattr(server_module, "build_server", fake_build_server)
        server_module.main(["--url", "http://cli:8047", "--max-rows", "7"])
        assert captured["cfg"].url == "http://cli:8047"
        assert captured["cfg"].max_rows == 7
