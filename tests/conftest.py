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

"""Shared pytest fixtures.

The suite must be hermetic: nothing in a developer's or CI runner's real
shell environment should be able to change test outcomes. `main()` and
`load_config()` read `os.environ` directly when no explicit `env=` is
passed, so a stray `DRILL_*` variable in the ambient environment (e.g. a
developer's local `.env` sourced into their shell) can otherwise leak into
a test that assumes defaults. Strip every `DRILL_*` variable before each
test runs so the whole suite behaves the same regardless of the ambient
environment.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _clean_drill_env(monkeypatch):
    """Remove all DRILL_* environment variables for the duration of a test."""
    for key in list(os.environ):
        if key.startswith("DRILL_"):
            monkeypatch.delenv(key, raising=False)
