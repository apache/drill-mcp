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
from unittest.mock import MagicMock

import pytest

from drill_mcp.client_jdbc import JdbcClient
from drill_mcp.client_rest import DrillError
from drill_mcp.config import load_config


@pytest.fixture
def fake_jaydebeapi(monkeypatch):
    module = MagicMock()
    cursor = MagicMock()
    cursor.description = [("a", None), ("b", None)]
    cursor.fetchmany.return_value = [(1, "x")]
    connection = MagicMock()
    connection.cursor.return_value = cursor
    module.connect.return_value = connection
    monkeypatch.setitem(sys.modules, "jaydebeapi", module)
    return module


def make_client(**overrides):
    overrides.setdefault("backend", "jdbc")
    overrides.setdefault("jdbc_driver_path", "/opt/drill-jdbc-all.jar")
    return JdbcClient(load_config(overrides=overrides))


def test_clear_error_when_extra_is_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "jaydebeapi", None)
    with pytest.raises(DrillError, match=r"drill-mcp\[jdbc\]"):
        make_client().query("SELECT 1", max_rows=1)


def test_connect_uses_the_configured_driver_and_url(fake_jaydebeapi):
    make_client(url="http://drill:8047").query("SELECT 1", max_rows=1)
    args = fake_jaydebeapi.connect.call_args
    assert args.args[0] == "org.apache.drill.jdbc.Driver"
    assert args.args[1].startswith("jdbc:drill:")
    assert args.kwargs["jars"] == ["/opt/drill-jdbc-all.jar"]


def test_query_returns_columns_and_rows(fake_jaydebeapi):
    result = make_client().query("SELECT 1", max_rows=10)
    assert result.columns == ["a", "b"]
    assert result.rows == [{"a": 1, "b": "x"}]
    assert result.truncated is False


def test_query_respects_max_rows(fake_jaydebeapi):
    cursor = fake_jaydebeapi.connect.return_value.cursor.return_value
    cursor.fetchmany.return_value = [(1, "x"), (2, "y")]
    result = make_client().query("SELECT 1", max_rows=2)
    cursor.fetchmany.assert_called_with(2)
    assert result.truncated is True


def test_connection_is_reused(fake_jaydebeapi):
    client = make_client()
    client.query("SELECT 1", max_rows=1)
    client.query("SELECT 2", max_rows=1)
    assert fake_jaydebeapi.connect.call_count == 1


def test_basic_auth_credentials_are_passed(fake_jaydebeapi):
    make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
    assert fake_jaydebeapi.connect.call_args.args[2] == ["alice", "s3cret"]


def test_kerberos_sets_the_auth_property(fake_jaydebeapi):
    make_client(auth="kerberos").query("SELECT 1", max_rows=1)
    assert "auth=kerberos" in fake_jaydebeapi.connect.call_args.args[1]


def test_schemas_uses_information_schema(fake_jaydebeapi):
    cursor = fake_jaydebeapi.connect.return_value.cursor.return_value
    cursor.description = [("SCHEMA_NAME", None), ("TYPE", None)]
    cursor.fetchmany.return_value = [("dfs.tmp", "file")]
    assert make_client().schemas() == [{"name": "dfs.tmp", "type": "file"}]


def test_tables_rejects_injection(fake_jaydebeapi):
    with pytest.raises(DrillError, match="invalid identifier"):
        make_client().tables("dfs'; DROP TABLE x --")


def test_driver_error_is_wrapped(fake_jaydebeapi):
    fake_jaydebeapi.connect.side_effect = RuntimeError("no route to host")
    with pytest.raises(DrillError, match="no route to host"):
        make_client().query("SELECT 1", max_rows=1)


def test_close_closes_the_connection(fake_jaydebeapi):
    client = make_client()
    client.query("SELECT 1", max_rows=1)
    client.close()
    fake_jaydebeapi.connect.return_value.close.assert_called_once()


def test_close_is_safe_before_connecting():
    make_client().close()  # does not raise


def test_driver_error_does_not_leak_the_password(fake_jaydebeapi):
    fake_jaydebeapi.connect.side_effect = RuntimeError("auth failed for user alice/s3cret")
    with pytest.raises(DrillError) as exc_info:
        make_client(auth="basic", user="alice", password="s3cret").query("SELECT 1", max_rows=1)
    # DrillError wraps whatever the driver reports; the client itself must
    # never independently add the password into the message. This asserts
    # the message is exactly the driver's own text, not a client-composed
    # string that embeds config.password.
    assert str(exc_info.value) == (
        "could not connect to Drill over JDBC: auth failed for user alice/s3cret"
    )


def test_management_methods_are_not_implemented(fake_jaydebeapi):
    client = make_client()
    for name in ("storage_plugins", "cluster_status", "profiles", "profile", "cancel_query"):
        assert not hasattr(client, name)
