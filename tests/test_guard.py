import pytest
import sqlglot
from sqlglot import exp

from drill_mcp.guard import Policy, PolicyError, check, matches_prefix


class TestSqlglotAssumptions:
    """Characterization tests: what the guard relies on sqlglot doing."""

    def test_parse_returns_one_statement_per_semicolon(self):
        assert len(sqlglot.parse("SELECT 1; SELECT 2", read="postgres")) == 2

    def test_select_parses_to_select(self):
        stmt = sqlglot.parse_one("SELECT * FROM dfs.tmp.foo", read="postgres")
        assert isinstance(stmt, exp.Select)

    def test_table_exposes_catalog_db_name(self):
        table = sqlglot.parse_one("SELECT * FROM dfs.tmp.foo", read="postgres").find(exp.Table)
        assert table.catalog == "dfs"
        assert table.db == "tmp"
        assert table.name == "foo"

    def test_two_part_name_populates_db_not_catalog(self):
        table = sqlglot.parse_one("SELECT * FROM sys.options", read="postgres").find(exp.Table)
        assert table.catalog == ""
        assert table.db == "sys"
        assert table.name == "options"

    def test_comments_are_stripped_by_the_tokenizer(self):
        stmt = sqlglot.parse_one("-- CREATE TABLE evil\nSELECT 1", read="postgres")
        assert isinstance(stmt, exp.Select)

    def test_ctas_target_is_reachable_from_this(self):
        stmt = sqlglot.parse_one(
            "CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.raw.src", read="postgres"
        )
        assert isinstance(stmt, exp.Create)
        target = stmt.this.this if isinstance(stmt.this, exp.Schema) else stmt.this
        assert isinstance(target, exp.Table)
        assert target.catalog == "dfs"
        assert target.db == "tmp"


OPEN = Policy(writable_plugins=("dfs.tmp",))
CLOSED = Policy()


class TestReadsAreAllowed:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1",
            "SELECT * FROM dfs.tmp.foo",
            "SELECT a, b FROM dfs.tmp.foo WHERE a > 1 ORDER BY b",
            "WITH x AS (SELECT * FROM dfs.tmp.foo) SELECT * FROM x",
            "SELECT * FROM dfs.tmp.a UNION SELECT * FROM dfs.tmp.b",
            "SELECT * FROM dfs.tmp.a JOIN dfs.tmp.b ON a.id = b.id",
            "SHOW SCHEMAS",
            "SHOW TABLES",
            "DESCRIBE dfs.tmp.foo",
        ],
    )
    def test_permitted(self, sql):
        check(sql, CLOSED)  # does not raise


class TestWritesAreDeniedByDefault:
    @pytest.mark.parametrize(
        "sql",
        [
            "CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.tmp.src",
            "CREATE VIEW dfs.tmp.v AS SELECT 1",
            "DROP TABLE dfs.tmp.foo",
            "DROP VIEW dfs.tmp.v",
            "INSERT INTO dfs.tmp.foo VALUES (1)",
            "ALTER SYSTEM SET `planner.width.max_per_node` = 4",
            "ALTER SESSION SET `store.format` = 'json'",
            "USE dfs.tmp",
            "REFRESH TABLE METADATA dfs.tmp.foo",
            "UPDATE dfs.tmp.foo SET a = 1",
            "DELETE FROM dfs.tmp.foo",
            "MERGE INTO dfs.tmp.foo USING dfs.tmp.src ON true WHEN MATCHED THEN DELETE",
        ],
    )
    def test_rejected_with_no_writable_plugins(self, sql):
        with pytest.raises(PolicyError):
            check(sql, CLOSED)


class TestWritesWithAnAllowlist:
    def test_ctas_into_allowed_plugin_permitted(self):
        check("CREATE TABLE dfs.tmp.out AS SELECT * FROM dfs.raw.src", OPEN)

    def test_create_view_into_allowed_plugin_permitted(self):
        check("CREATE VIEW dfs.tmp.v AS SELECT 1", OPEN)

    def test_drop_in_allowed_plugin_permitted(self):
        check("DROP TABLE dfs.tmp.old", OPEN)

    def test_ctas_into_other_plugin_rejected(self):
        with pytest.raises(PolicyError, match="writable_plugins"):
            check("CREATE TABLE s3.bucket.out AS SELECT 1", OPEN)

    def test_sibling_workspace_rejected(self):
        with pytest.raises(PolicyError):
            check("CREATE TABLE dfs.raw.out AS SELECT 1", OPEN)

    def test_plugin_level_entry_permits_any_workspace(self):
        check("CREATE TABLE dfs.raw.out AS SELECT 1", Policy(writable_plugins=("dfs",)))

    def test_matching_is_case_insensitive(self):
        check("CREATE TABLE DFS.TMP.OUT AS SELECT 1", OPEN)

    def test_insert_still_rejected_even_when_plugin_writable(self):
        with pytest.raises(PolicyError):
            check("INSERT INTO dfs.tmp.foo VALUES (1)", OPEN)

    def test_unqualified_target_rejected(self):
        with pytest.raises(PolicyError):
            check("CREATE TABLE bare AS SELECT 1", OPEN)


class TestInjectionAttempts:
    def test_write_hidden_in_a_comment_is_not_a_write(self):
        check("-- CREATE TABLE dfs.tmp.x AS SELECT 1\nSELECT 1", CLOSED)

    def test_write_inside_a_string_literal_is_not_a_write(self):
        check("SELECT 'DROP TABLE dfs.tmp.foo' AS note", CLOSED)

    def test_stacked_statements_rejected(self):
        with pytest.raises(PolicyError, match="one statement"):
            check("SELECT 1; DROP TABLE dfs.tmp.foo", CLOSED)

    def test_stacked_statements_rejected_even_when_both_are_reads(self):
        with pytest.raises(PolicyError, match="one statement"):
            check("SELECT 1; SELECT 2", CLOSED)

    def test_trailing_semicolon_is_fine(self):
        check("SELECT 1;", CLOSED)

    def test_empty_sql_rejected(self):
        with pytest.raises(PolicyError):
            check("   ", CLOSED)

    def test_unparseable_sql_rejected(self):
        with pytest.raises(PolicyError, match="parse"):
            check("SELECT FROM WHERE ((", CLOSED)

    def test_tokenizer_failure_is_a_policy_error_not_a_crash(self):
        # An unterminated string literal raises sqlglot's TokenError, a sibling
        # of ParseError under SqlglotError, not a subclass of it. A guard that
        # only catches ParseError lets this escape uncaught.
        with pytest.raises(PolicyError, match="parse"):
            check("SELECT * FROM t WHERE note = 'it''s", CLOSED)


class TestMatchesPrefix:
    def test_exact_match(self):
        assert matches_prefix("dfs.tmp", ["dfs.tmp"])

    def test_parent_entry_matches_child(self):
        assert matches_prefix("dfs.tmp", ["dfs"])

    def test_child_entry_does_not_match_parent(self):
        assert not matches_prefix("dfs", ["dfs.tmp"])

    def test_sibling_does_not_match(self):
        assert not matches_prefix("dfs.raw", ["dfs.tmp"])

    def test_case_insensitive(self):
        assert matches_prefix("DFS.TMP", ["dfs.tmp"])

    def test_no_partial_component_match(self):
        assert not matches_prefix("dfsx.tmp", ["dfs"])

    def test_empty_entries_never_match(self):
        assert not matches_prefix("dfs.tmp", [])


class TestEmbeddedWritesInsideReadRoots:
    """A statement whose root node is a read type can still contain a write in
    its subtree. Checking only the root type is not enough — the safety
    property must not depend on Drill's parser being narrower than sqlglot's
    Postgres dialect. Neither of these is executable Drill SQL, but the guard
    must not rely on that.
    """

    def test_write_inside_a_cte_is_rejected(self):
        with pytest.raises(PolicyError):
            check(
                "WITH x AS (INSERT INTO dfs.tmp.foo VALUES (1) RETURNING *) SELECT * FROM x",
                CLOSED,
            )

    def test_select_into_is_rejected(self):
        with pytest.raises(PolicyError):
            check("SELECT * INTO dfs.tmp.newt FROM dfs.raw.src", CLOSED)


class TestExplainRecursesIntoItsBody:
    """EXPLAIN is not blanket-safe: sqlglot parses it as an opaque exp.Command,
    so the guard must strip the leading EXPLAIN / EXPLAIN PLAN FOR keywords and
    re-run the full check on what remains, rather than trusting the keyword
    alone.
    """

    def test_explain_of_a_read_is_permitted(self):
        check("EXPLAIN PLAN FOR SELECT * FROM dfs.tmp.t", CLOSED)

    def test_explain_of_a_write_into_disallowed_plugin_is_rejected(self):
        with pytest.raises(PolicyError):
            check("EXPLAIN PLAN FOR CREATE TABLE s3.out AS SELECT 1", CLOSED)

    def test_explain_of_a_write_into_allowed_plugin_is_permitted(self):
        check("EXPLAIN PLAN FOR CREATE TABLE dfs.tmp.out AS SELECT 1", OPEN)

    def test_explain_of_a_hidden_schema_is_rejected(self):
        hidden = Policy(hidden_schemas=("sys",))
        with pytest.raises(PolicyError):
            check("EXPLAIN PLAN FOR SELECT * FROM sys.options", hidden)

    def test_deeply_nested_explain_is_rejected_not_a_stack_overflow(self):
        with pytest.raises(PolicyError):
            check("EXPLAIN " * 10 + "SELECT 1", CLOSED)
