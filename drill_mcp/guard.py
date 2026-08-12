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

"""SQL policy enforcement. Pure: string in, decision out, no I/O.

Deny by default. Reads are permitted; a write is permitted only when its target
resolves into a plugin the operator explicitly listed in `writable_plugins`.

A real parser rather than a regex, deliberately: a regex guard is defeated by
`-- CREATE TABLE` in a comment, by `'DROP TABLE'` inside a string literal, and
by statement stacking. This module is the only thing standing between a model
and the user's data.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

import sqlglot
from sqlglot import exp

DIALECT = "drill"  # sqlglot ships a native Drill dialect (sqlglot.dialects.drill.Drill).

# Commands sqlglot does not model as expressions, but which cannot write.
# EXPLAIN is handled separately (see _check_write): it is not blanket-safe
# because its body can itself be a write.
_SAFE_COMMANDS = {"SHOW", "DESCRIBE", "DESC"}

_READ_TYPES = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery, exp.Describe)

# Node types that indicate a write is embedded somewhere inside a statement
# whose root node is a read type (e.g. `WITH x AS (INSERT ...) SELECT * FROM x`,
# or `SELECT ... INTO ...`). Checking only the root type is not enough: the
# safety property must not depend on sqlglot's Drill grammar rejecting these
# forms outright — a write hidden deeper in the tree must still be caught.
_EMBEDDED_WRITE_TYPES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Into,
)

# EXPLAIN unwraps its body and re-checks it recursively; this bounds
# `EXPLAIN EXPLAIN EXPLAIN ...` so a malicious input cannot blow the stack.
_MAX_EXPLAIN_DEPTH = 5


class PolicyError(Exception):
    """Raised when a statement is not permitted. The message is shown to the caller."""


@dataclass(frozen=True)
class Policy:
    writable_plugins: tuple[str, ...] = ()
    hidden_schemas: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, cfg) -> Policy:
        return cls(
            writable_plugins=tuple(cfg.writable_plugins),
            hidden_schemas=tuple(cfg.hidden_schemas),
        )


def matches_prefix(qualified: str, entries: Iterable[str]) -> bool:
    """True if any entry is a dotted-component prefix of `qualified`.

    Component-wise so that `dfs` matches `dfs.tmp` but not `dfsx.tmp`.
    """
    parts = [p.lower() for p in qualified.split(".") if p]
    if not parts:
        return False
    for entry in entries:
        entry_parts = [p.lower() for p in entry.split(".") if p]
        if entry_parts and parts[: len(entry_parts)] == entry_parts:
            return True
    return False


def is_show_command(sql: str) -> bool:
    """True if `sql` is any `SHOW ...` statement (`SCHEMAS`, `DATABASES`,
    `TABLES`, `FILES`, ...).

    This used to try to positively identify `SHOW SCHEMAS`/`SHOW DATABASES`
    specifically, by inspecting the text of whatever sqlglot left in the
    Command's `expression` literal. Three attempts at that (a regex over the
    raw SQL, exact-equality against the literal, comparing only its first
    token after stripping `/* */` comments) all failed the same way: Drill's
    `SHOW` grammar has no dedicated sqlglot node, so everything after the
    keyword — including `LIKE '...'` clauses, embedded comments, and
    unbalanced comment delimiters like `SHOW */ SCHEMAS` — collapses into one
    opaque literal, and any classifier over that text has some spelling it
    fails to recognise. A classifier that fails open on the shapes it does
    not recognise is the wrong shape entirely for a security filter: it must
    fail closed instead.

    So this checks only whether the statement is a `SHOW` command at all —
    one already-parsed field (`statement.this == "SHOW"`), no text parsing.
    The caller filters the first column of *any* `SHOW` command's result set
    when hidden_schemas is configured, accepting that `SHOW TABLES`/`SHOW
    FILES` rows are incidentally run through the same filter (a table or file
    literally named `sys`, for a `hidden_schemas: [sys]` policy, would be
    dropped) in exchange for the property that no `SHOW` spelling can leak a
    hidden schema by evading a classifier.

    Returns False rather than raising if `sql` does not parse: by the time
    this is called, `check()` has already accepted the statement, so a parse
    failure here would be a bug in this function, not a policy decision to
    surface.
    """
    try:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except (sqlglot.errors.SqlglotError, RecursionError):
        return False
    if len(statements) != 1:
        return False
    statement = statements[0]
    return isinstance(statement, exp.Command) and str(statement.this or "").upper() == "SHOW"


def check(sql: str, policy: Policy) -> None:
    """Return None if `sql` is permitted under `policy`; raise PolicyError otherwise."""
    _check(sql, policy, depth=0)


def _check(sql: str, policy: Policy, depth: int) -> None:
    if not sql or not sql.strip():
        raise PolicyError("empty SQL statement")

    try:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except Exception as exc:
        # Catches ParseError and TokenError (siblings under SqlglotError, not
        # parent/child) as well as anything else the parser can throw on
        # adversarial input, such as a RecursionError from deeply nested
        # parentheses. A parse failure of any kind must be a PolicyError,
        # never an uncaught crash — scoped to this call only, so a PolicyError
        # raised by the policy logic further down is never caught here.
        raise PolicyError(
            f"could not parse SQL, so it cannot be checked against policy and is rejected: {exc}"
        ) from exc

    if len(statements) != 1:
        raise PolicyError(f"exactly one statement per call is permitted, got {len(statements)}")

    statement = statements[0]
    _check_hidden(statement, policy)
    _check_write(statement, policy, depth)


def _check_write(statement: exp.Expression, policy: Policy, depth: int) -> None:
    if isinstance(statement, _READ_TYPES):
        embedded = statement.find(*_EMBEDDED_WRITE_TYPES)
        if embedded is not None:
            raise PolicyError(
                f"statement contains an embedded {embedded.key.upper()}, which is not permitted"
            )
        return

    if isinstance(statement, exp.Command):
        keyword = str(statement.this or "").upper()
        if keyword == "EXPLAIN":
            if depth >= _MAX_EXPLAIN_DEPTH:
                raise PolicyError("too many nested EXPLAIN statements")
            body = _explain_body(statement)
            if not body.strip():
                raise PolicyError("EXPLAIN with no statement body is not permitted")
            _check(body, policy, depth + 1)
            return
        if keyword in _SAFE_COMMANDS:
            return
        raise PolicyError(f"statement type {keyword or 'UNKNOWN'} is not permitted")

    if isinstance(statement, (exp.Create, exp.Drop)):
        kind = (statement.args.get("kind") or "").upper()
        if kind not in {"TABLE", "VIEW"}:
            raise PolicyError(f"{statement.key.upper()} {kind or 'UNKNOWN'} is not permitted")
        target = _write_target(statement)
        if target is None:
            raise PolicyError("could not determine the target of this statement, rejecting")
        qualified = _schema_prefix(target)
        if not qualified:
            raise PolicyError(
                f"write target '{target.name}' is not schema-qualified; "
                "qualify it with a plugin listed in writable_plugins"
            )
        if not matches_prefix(qualified, policy.writable_plugins):
            raise PolicyError(
                f"writes to '{qualified}' are not permitted; "
                f"add it to writable_plugins to allow this (currently: "
                f"{list(policy.writable_plugins) or 'none'})"
            )
        return

    raise PolicyError(f"statement type {statement.key.upper()} is not permitted")


def _explain_body(statement: exp.Command) -> str:
    """Extract the SQL text following `EXPLAIN` (and an optional `PLAN FOR`).

    sqlglot has no Drill EXPLAIN grammar, so the whole statement falls back to
    `exp.Command`, with everything after the leading keyword left as raw,
    unparsed text. We recurse `check()` over that text rather than trusting
    the leading keyword alone — otherwise `EXPLAIN PLAN FOR CREATE TABLE ...`
    would bypass the write-target allowlist entirely.
    """
    remainder = statement.args.get("expression")
    text = remainder.this if isinstance(remainder, exp.Literal) else str(remainder or "")
    return re.sub(r"^\s*PLAN\s+FOR\s+", "", text, flags=re.IGNORECASE)


def _write_target(statement: exp.Expression) -> exp.Table | None:
    target = statement.this
    if isinstance(target, exp.Schema):
        target = target.this
    return target if isinstance(target, exp.Table) else None


def _schema_prefix(table: exp.Table) -> str:
    return ".".join(part for part in (table.catalog, table.db) if part)


def _check_hidden(statement: exp.Expression, policy: Policy) -> None:
    if not policy.hidden_schemas:
        return

    for table in statement.find_all(exp.Table):
        prefix = _schema_prefix(table)
        if prefix and matches_prefix(prefix, policy.hidden_schemas):
            raise PolicyError(f"schema '{prefix}' is hidden by configuration")

    if isinstance(statement, exp.Command):
        # ponytail: sqlglot leaves SHOW's remainder as raw text, so scan it for
        # hidden names. Safe because the tokenizer already stripped comments and
        # string literals cannot appear in a SHOW target. Upgrade to a real parse
        # if Drill's SHOW grammar ever gains an expression argument.
        remainder = str(statement.args.get("expression") or "")
        for entry in policy.hidden_schemas:
            head = entry.split(".")[0]
            if re.search(rf"\b{re.escape(head)}\b", remainder, re.IGNORECASE):
                raise PolicyError(f"schema '{entry}' is hidden by configuration")
