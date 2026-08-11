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
