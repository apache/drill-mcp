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

from drill_mcp.client_rest import DrillError, QueryResult
from drill_mcp.config import load_config
from drill_mcp.server import DrillTools, ToolError


def make_tools(client=None, **overrides):
    client = client or MagicMock()
    return DrillTools(load_config(overrides=overrides), client)


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

    def test_cancel_query(self):
        client = MagicMock()
        client.cancel_query.return_value = "Cancelled"
        assert make_tools(client).cancel_query("abc") == "Cancelled"

    def test_management_tools_are_unavailable_on_a_client_without_them(self):
        client = MagicMock(spec=["query", "schemas", "tables", "columns"])
        with pytest.raises(ToolError, match="REST"):
            make_tools(client).cluster_status()

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
    """SHOW is evaluated server-side by Drill, so rows are filtered on return."""

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
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"], [{"SCHEMA_NAME": "sys"}]
        )
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
        result = make_tools(client, hidden_schemas=["sys"]).run_query(
            "/* x */ SHOW SCHEMAS"
        )
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

    def test_show_filtering_is_case_insensitive(self):
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("show schemas")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

        client.query.return_value = QueryResult(
            ["SCHEMA_NAME"],
            [{"SCHEMA_NAME": "sys"}, {"SCHEMA_NAME": "dfs.tmp"}],
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("ShOw ScHeMaS")
        assert result["rows"] == [{"SCHEMA_NAME": "dfs.tmp"}]

    def test_show_tables_rows_are_not_filtered(self):
        """SHOW TABLES rows are table names, not schema names; filtering them
        against hidden_schemas would be wrong."""
        client = MagicMock()
        client.query.return_value = QueryResult(
            ["TABLE_NAME"], [{"TABLE_NAME": "sys"}]
        )
        result = make_tools(client, hidden_schemas=["sys"]).run_query("SHOW TABLES")
        assert result["rows"] == [{"TABLE_NAME": "sys"}]
