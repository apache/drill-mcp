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

from drill_mcp.redact import REDACTED, redact


def test_redacts_password_key():
    assert redact({"password": "hunter2"}) == {"password": REDACTED}


def test_redaction_is_case_insensitive():
    assert redact({"PassWord": "hunter2"}) == {"PassWord": REDACTED}


def test_redacts_all_sensitive_key_patterns():
    source = {
        "accessKey": "AKIA",
        "access_key": "AKIA",
        "secretKey": "s",
        "token": "t",
        "credential": "c",
        "privateKey": "p",
        "oauthToken": "o",
    }
    assert all(v == REDACTED for v in redact(source).values())


def test_leaves_innocuous_keys_alone():
    assert redact({"type": "file", "connection": "s3a://bucket"}) == {
        "type": "file",
        "connection": "s3a://bucket",
    }


def test_recurses_into_nested_dicts():
    source = {"config": {"aws": {"awsSecretAccessKey": "s"}}}
    assert redact(source)["config"]["aws"]["awsSecretAccessKey"] == REDACTED


def test_recurses_into_lists():
    source = {"plugins": [{"password": "a"}, {"password": "b"}]}
    assert [p["password"] for p in redact(source)["plugins"]] == [REDACTED, REDACTED]


def test_does_not_mutate_the_input():
    source = {"password": "hunter2"}
    redact(source)
    assert source["password"] == "hunter2"


def test_redacts_whole_subtree_under_a_sensitive_key():
    source = {"credentials": {"user": "alice", "pass": "x"}}
    assert redact(source)["credentials"] == REDACTED


def test_passes_through_scalars():
    assert redact("plain") == "plain"
    assert redact(42) == 42
    assert redact(None) is None


def test_realistic_s3_plugin_config():
    plugin = {
        "name": "s3",
        "config": {
            "type": "file",
            "connection": "s3a://my-bucket",
            "config": {
                "fs.s3a.access.key": "AKIAEXAMPLE",
                "fs.s3a.secret.key": "verysecret",
                "fs.s3a.endpoint": "s3.amazonaws.com",
            },
            "workspaces": {"root": {"location": "/", "writable": False}},
        },
    }
    result = redact(plugin)
    inner = result["config"]["config"]
    assert inner["fs.s3a.access.key"] == REDACTED
    assert inner["fs.s3a.secret.key"] == REDACTED
    assert inner["fs.s3a.endpoint"] == "s3.amazonaws.com"
    assert result["config"]["workspaces"]["root"]["location"] == "/"


def test_redacts_credentials_provider_wholly():
    source = {"credentialsProvider": {"clientID": "x"}}
    assert redact(source)["credentialsProvider"] == REDACTED


def test_redacts_gcs_credentials_json():
    source = {"credentialsJson": '{"type": "service_account", "private_key": "..."}'}
    assert redact(source)["credentialsJson"] == REDACTED


def test_redacts_credentials_b64():
    source = {"credentialsB64": "base64encodedkey"}
    assert redact(source)["credentialsB64"] == REDACTED


def test_redacts_credentials_provider_type():
    source = {"credentialsProviderType": "com.amazonaws.auth.DefaultAWSCredentialsProviderChain"}
    assert redact(source)["credentialsProviderType"] == REDACTED


def test_redacts_authorization_header():
    source = {"Authorization": "Bearer token123"}
    assert redact(source)["Authorization"] == REDACTED


def test_redacts_passphrase():
    source = {"passphrase": "secret"}
    assert redact(source)["passphrase"] == REDACTED


def test_redacts_keytab():
    source = {"keytab": "/path/to/user.keytab"}
    assert redact(source)["keytab"] == REDACTED


def test_redacts_principal():
    source = {"principal": "user@REALM"}
    assert redact(source)["principal"] == REDACTED


def test_passes_through_tuples():
    source = ({"password": "x"},)
    result = redact(source)
    assert isinstance(result, tuple)
    assert result[0]["password"] == REDACTED
