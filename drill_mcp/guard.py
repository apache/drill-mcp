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

DIALECT = "postgres"  # closest available fit for Drill's Calcite SQL

# Commands sqlglot does not model as expressions, but which cannot write.
_SAFE_COMMANDS = {"SHOW", "DESCRIBE", "DESC", "EXPLAIN"}

_READ_TYPES = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery, exp.Describe)


class PolicyError(Exception):
    """Raised when a statement is not permitted. The message is shown to the caller."""


@dataclass(frozen=True)
class Policy:
    writable_plugins: tuple[str, ...] = ()
    hidden_schemas: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, cfg) -> "Policy":
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


def check(sql: str, policy: Policy) -> None:
    """Return None if `sql` is permitted under `policy`; raise PolicyError otherwise."""
    if not sql or not sql.strip():
        raise PolicyError("empty SQL statement")

    try:
        statements = [s for s in sqlglot.parse(sql, read=DIALECT) if s is not None]
    except sqlglot.ParseError as exc:
        raise PolicyError(
            f"could not parse SQL, so it cannot be checked against policy and is rejected: {exc}"
        ) from exc

    if len(statements) != 1:
        raise PolicyError(
            f"exactly one statement per call is permitted, got {len(statements)}"
        )

    statement = statements[0]
    _check_hidden(statement, policy)
    _check_write(statement, policy)


def _check_write(statement: exp.Expression, policy: Policy) -> None:
    if isinstance(statement, _READ_TYPES):
        return

    if isinstance(statement, exp.Command):
        keyword = str(statement.this or "").upper()
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
