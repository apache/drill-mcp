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

import pytest
from pydantic import ValidationError

from drill_mcp.config import Config, ConfigError, load_config


def test_defaults_are_conservative():
    cfg = load_config(env={})
    assert cfg.url == "http://localhost:8047"
    assert cfg.backend == "rest"
    assert cfg.auth == "none"
    assert cfg.max_rows == 1000
    assert cfg.timeout_seconds == 60
    assert cfg.writable_plugins == []
    assert cfg.hidden_schemas == []


def test_loads_from_yaml_file(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("url: http://drill:8047\nmax_rows: 50\nwritable_plugins: [dfs.tmp]\n")
    cfg = load_config(str(path), env={})
    assert cfg.url == "http://drill:8047"
    assert cfg.max_rows == 50
    assert cfg.writable_plugins == ["dfs.tmp"]


def test_loads_numeric_string_from_yaml_file(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text('max_rows: "50"\n')
    cfg = load_config(str(path), env={})
    assert cfg.max_rows == 50


def test_env_overrides_file(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("url: http://from-file:8047\n")
    cfg = load_config(str(path), env={"DRILL_URL": "http://from-env:8047"})
    assert cfg.url == "http://from-env:8047"


def test_cli_overrides_env(tmp_path):
    cfg = load_config(
        env={"DRILL_URL": "http://from-env:8047"},
        overrides={"url": "http://from-cli:8047"},
    )
    assert cfg.url == "http://from-cli:8047"


def test_credentials_read_from_env():
    cfg = load_config(env={"DRILL_USER": "alice", "DRILL_PASSWORD": "s3cret", "DRILL_AUTH": "basic"})
    assert cfg.user == "alice"
    assert cfg.password == "s3cret"


def test_unknown_key_is_an_error(tmp_path):
    path = tmp_path / "drill.yaml"
    path.write_text("uurl: http://typo:8047\n")
    with pytest.raises(ConfigError, match="uurl"):
        load_config(str(path), env={})


def test_basic_auth_requires_credentials():
    with pytest.raises(ConfigError, match="user"):
        load_config(env={}, overrides={"auth": "basic"})


def test_jdbc_backend_requires_driver_path():
    with pytest.raises(ConfigError, match="jdbc_driver_path"):
        load_config(env={}, overrides={"backend": "jdbc"})


def test_invalid_backend_is_an_error():
    with pytest.raises(ConfigError):
        load_config(env={}, overrides={"backend": "carrier-pigeon"})


def test_max_rows_must_be_positive():
    with pytest.raises(ConfigError):
        load_config(env={}, overrides={"max_rows": 0})


def test_missing_config_file_is_an_error():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/drill.yaml", env={})


def test_config_is_immutable():
    cfg = load_config(env={})
    with pytest.raises(ValidationError, match="frozen"):
        cfg.url = "http://elsewhere:8047"


def test_a_non_string_password_does_not_appear_in_the_error_message():
    # pydantic's default ValidationError text embeds `input_value=...` for
    # every error -- e.g. an unquoted `password: 12345` in YAML produces
    # "input_value=12345" verbatim. ConfigError must not echo that: `main()`
    # prints it to stderr, and any log capturing stderr would then carry the
    # (would-be) password in plaintext.
    with pytest.raises(ConfigError) as exc:
        load_config(env={}, overrides={"password": 12345})
    assert "12345" not in str(exc.value)
