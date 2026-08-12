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

"""Recursive secret redaction for anything returned to an MCP client.

Storage plugin configurations routinely carry AWS keys, JDBC passwords, and
OAuth tokens. Tool output goes to a model and often on to a third-party API, so
this is a trust boundary and is not configurable off.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "***REDACTED***"

# Matches anywhere in the key, so `fs.s3a.secret.key` and `awsSecretAccessKey`
# are both caught. Deliberately broad: a false redaction is a cosmetic problem,
# a missed one is a leaked credential.
_SENSITIVE = re.compile(
    r"password|passwd|secret|credential|token|access[._-]?key|private[._-]?key|api[._-]?key|session[._-]?key|authorization|passphrase|keytab|principal",
    re.IGNORECASE,
)

# The key-based check above only catches secrets that live at a sensitive
# *key*. A storage-plugin config routinely carries secrets embedded inside an
# ordinary-looking *value* instead -- a JDBC/S3-style URL with userinfo
# (`s3a://AKIA:secret@bucket`), or a connection string with a `password=`/
# `secret=`/`token=` query parameter. Both shapes are real Drill storage
# plugin configs, so string values are scrubbed too, not just keys.
#
# Matches "scheme://user:pass@" and keeps everything else (scheme, host,
# path) intact -- only the credential pair between "//" and "@" is replaced.
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+:[^/@\s]*@")

# Matches a `?key=value` or `&key=value` query parameter whose key looks like
# a secret, and replaces only the value -- the `?`/`&` and key name are kept
# so the rest of the string still parses as the same shape of URL.
_QUERY_SECRET = re.compile(
    r"(?P<prefix>[?&](?:password|secret|api_?key|token)=)[^&]*",
    re.IGNORECASE,
)


def _scrub_value(value: str) -> str:
    """Strip credentials embedded inside a string value, not just its key."""
    value = _URL_USERINFO.sub(lambda m: f"{m.group('scheme')}{REDACTED}@", value)
    value = _QUERY_SECRET.sub(lambda m: f"{m.group('prefix')}{REDACTED}", value)
    return value


def redact(value: Any) -> Any:
    """Return a copy of `value` with sensitive-looking values replaced."""
    if isinstance(value, dict):
        return {
            key: REDACTED if _SENSITIVE.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return _scrub_value(value)
    return value
