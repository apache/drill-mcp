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

"""Configuration loading and validation.

Precedence, later overriding earlier: config file, environment, CLI overrides.
Validation happens at startup, not at first tool call — a server that starts is
a server that is configured correctly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or internally inconsistent."""


_ENV_MAP = {
    "DRILL_URL": "url",
    "DRILL_BACKEND": "backend",
    "DRILL_AUTH": "auth",
    "DRILL_USER": "user",
    "DRILL_PASSWORD": "password",
    "DRILL_MAX_ROWS": "max_rows",
    "DRILL_TIMEOUT_SECONDS": "timeout_seconds",
    "DRILL_JDBC_DRIVER_PATH": "jdbc_driver_path",
}

_INT_FIELDS = {"max_rows", "timeout_seconds"}


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = "http://localhost:8047"
    backend: Literal["rest", "jdbc"] = "rest"
    auth: Literal["none", "basic", "kerberos"] = "none"
    user: str | None = None
    password: str | None = None
    max_rows: int = Field(default=1000, gt=0)
    timeout_seconds: int = Field(default=60, gt=0)
    writable_plugins: list[str] = Field(default_factory=list)
    hidden_schemas: list[str] = Field(default_factory=list)
    jdbc_driver_path: str | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "Config":
        if self.auth == "basic" and not (self.user and self.password):
            raise ValueError("auth: basic requires both user and password")
        if self.backend == "jdbc" and not self.jdbc_driver_path:
            raise ValueError("backend: jdbc requires jdbc_driver_path")
        return self


def load_config(
    path: str | None = None,
    env: Mapping[str, str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    env = os.environ if env is None else env
    values: dict[str, Any] = {}

    if path is not None:
        file_path = Path(path)
        if not file_path.is_file():
            raise ConfigError(f"config file not found: {path}")
        try:
            loaded = yaml.safe_load(file_path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"config file is not valid YAML: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigError("config file must contain a YAML mapping at the top level")
        values.update(loaded)

    for env_key, field in _ENV_MAP.items():
        if env_key in env:
            values[field] = env[env_key]

    values.update(overrides or {})

    for field in _INT_FIELDS:
        if isinstance(values.get(field), str):
            try:
                values[field] = int(values[field])
            except ValueError as exc:
                raise ConfigError(f"{field} must be an integer") from exc

    try:
        return Config(**values)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
