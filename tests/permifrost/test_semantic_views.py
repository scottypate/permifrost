import pytest
import yaml

from permifrost.entities import EntityGenerator
from permifrost.snowflake_connector import SnowflakeConnector
from permifrost.snowflake_grants import SnowflakeGrantsGenerator
from permifrost.spec_file_loader import ensure_valid_schema

ROLE = "functional_role"
SPEC_DBS = {"database_1", "database_2", "shared_database_1"}
SHARED_DBS = {"shared_database_1"}


@pytest.fixture
def patch_conn(mocker):
    """Patch the connector so no Snowflake connection is needed."""
    mocker.patch.object(SnowflakeConnector, "__init__", lambda x: None)

    def _patch(semantic_views=(), schemas=("database_1.schema_1",)):
        mocker.patch.object(
            SnowflakeConnector, "show_semantic_views", return_value=list(semantic_views)
        )
        mocker.patch.object(
            SnowflakeConnector, "show_schemas", return_value=list(schemas)
        )
        mocker.patch.object(SnowflakeConnector, "show_tables", return_value=[])
        mocker.patch.object(SnowflakeConnector, "show_views", return_value=[])

    return _patch


def generate(grants_to_role, semantic_views, only_new=True):
    generator = SnowflakeGrantsGenerator(grants_to_role, {})
    commands = generator.generate_semantic_view_grants(
        ROLE, semantic_views, SHARED_DBS, SPEC_DBS
    )
    return sorted(c["sql"] for c in commands if not (only_new and c["already_granted"]))


class TestSemanticViewGrants:
    def test_named_semantic_view(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        assert generate({}, ["database_1.schema_1.arr_sv"]) == [
            "GRANT select, references ON semantic view database_1.schema_1.arr_sv "
            "TO ROLE functional_role"
        ]

    def test_missing_named_semantic_view_is_not_granted(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.other_sv"])
        assert generate({}, ["database_1.schema_1.arr_sv"]) == []

    def test_schema_wildcard_grants_all_and_future(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        assert generate({}, ["database_1.schema_1.*"]) == [
            "GRANT select, references ON ALL semantic views IN schema "
            "database_1.schema_1 TO ROLE functional_role",
            "GRANT select, references ON FUTURE semantic views IN schema "
            "database_1.schema_1 TO ROLE functional_role",
        ]

    def test_database_wildcard_grants_database_and_each_schema(self, patch_conn):
        patch_conn(schemas=["database_1.schema_1", "database_1.schema_2"])
        assert generate({}, ["database_1.*.*"]) == [
            "GRANT select, references ON ALL semantic views IN database "
            "database_1 TO ROLE functional_role",
            "GRANT select, references ON ALL semantic views IN schema "
            "database_1.schema_1 TO ROLE functional_role",
            "GRANT select, references ON ALL semantic views IN schema "
            "database_1.schema_2 TO ROLE functional_role",
            "GRANT select, references ON FUTURE semantic views IN database "
            "database_1 TO ROLE functional_role",
            "GRANT select, references ON FUTURE semantic views IN schema "
            "database_1.schema_1 TO ROLE functional_role",
            "GRANT select, references ON FUTURE semantic views IN schema "
            "database_1.schema_2 TO ROLE functional_role",
        ]

    def test_shared_database_is_skipped(self, patch_conn):
        patch_conn()
        assert generate({}, ["shared_database_1.schema_1.*"]) == []

    def test_already_granted_is_flagged(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        granted = {
            ROLE: {
                "select": {"semantic_view": ["database_1.schema_1.arr_sv"]},
                "references": {"semantic_view": ["database_1.schema_1.arr_sv"]},
            }
        }
        assert generate(granted, ["database_1.schema_1.arr_sv"]) == []

    def test_partially_granted_is_regranted(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        granted = {ROLE: {"select": {"semantic_view": ["database_1.schema_1.arr_sv"]}}}
        assert generate(granted, ["database_1.schema_1.arr_sv"]) == [
            "GRANT select, references ON semantic view database_1.schema_1.arr_sv "
            "TO ROLE functional_role"
        ]


class TestSemanticViewRevokes:
    def test_undeclared_grants_are_revoked_per_privilege(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        granted = {
            ROLE: {
                "select": {
                    "semantic_view": [
                        "database_1.schema_1.arr_sv",
                        "database_1.schema_1.old_sv",
                    ]
                },
                "references": {"semantic_view": ["database_1.schema_1.old_sv"]},
            }
        }
        assert generate(granted, ["database_1.schema_1.arr_sv"]) == [
            "GRANT select, references ON semantic view database_1.schema_1.arr_sv "
            "TO ROLE functional_role",
            "REVOKE references ON semantic view database_1.schema_1.old_sv "
            "FROM ROLE functional_role",
            "REVOKE select ON semantic view database_1.schema_1.old_sv "
            "FROM ROLE functional_role",
        ]

    def test_undeclared_monitor_grant_is_revoked_but_never_granted(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        granted = {
            ROLE: {
                "monitor": {
                    "semantic_view": [
                        "database_1.schema_1.arr_sv",
                        "database_1.schema_1.old_sv",
                    ]
                }
            }
        }
        assert generate(granted, ["database_1.schema_1.arr_sv"]) == [
            "GRANT select, references ON semantic view database_1.schema_1.arr_sv "
            "TO ROLE functional_role",
            "REVOKE monitor ON semantic view database_1.schema_1.old_sv "
            "FROM ROLE functional_role",
        ]

    def test_undeclared_future_grants_are_revoked(self, patch_conn):
        patch_conn()
        granted = {
            ROLE: {
                "select": {"semantic_view": ["database_1.schema_1.<semantic_view>"]},
                "references": {
                    "semantic_view": ["database_1.schema_1.<semantic_view>"]
                },
            }
        }
        assert generate(granted, []) == [
            "REVOKE references ON FUTURE semantic views IN schema "
            "database_1.schema_1 FROM ROLE functional_role",
            "REVOKE select ON FUTURE semantic views IN schema "
            "database_1.schema_1 FROM ROLE functional_role",
        ]

    def test_declared_future_grants_are_kept(self, patch_conn):
        patch_conn()
        granted = {
            ROLE: {
                "select": {"semantic_view": ["database_1.schema_1.<semantic_view>"]},
                "references": {
                    "semantic_view": ["database_1.schema_1.<semantic_view>"]
                },
            }
        }
        assert generate(granted, ["database_1.schema_1.*"], only_new=False)
        assert not [
            sql
            for sql in generate(granted, ["database_1.schema_1.*"])
            if sql.startswith("REVOKE")
        ]

    def test_grants_outside_spec_databases_are_ignored(self, patch_conn):
        patch_conn()
        granted = {ROLE: {"select": {"semantic_view": ["other_db.s.sv"]}}}
        assert generate(granted, []) == []

    def test_semantic_view_rows_do_not_leak_into_table_view_handling(self, patch_conn):
        """A role holding only semantic view grants yields no table/view revokes."""
        patch_conn()
        generator = SnowflakeGrantsGenerator(
            {
                ROLE: {
                    "select": {"semantic_view": ["database_1.schema_1.sv"]},
                    "references": {"semantic_view": ["database_1.schema_1.sv"]},
                }
            },
            {},
        )
        commands = generator.generate_table_and_view_grants(
            ROLE, {"read": [], "write": []}, SHARED_DBS, SPEC_DBS
        )
        assert commands == []

    def test_table_and_view_rows_do_not_leak_into_semantic_view_handling(
        self, patch_conn
    ):
        patch_conn()
        granted = {
            ROLE: {
                "select": {
                    "table": ["database_1.schema_1.t"],
                    "view": ["database_1.schema_1.v"],
                },
                "references": {"table": ["database_1.schema_1.t"]},
            }
        }
        assert generate(granted, []) == []

    def test_spec_with_both_tables_and_semantic_views(self, patch_conn):
        patch_conn(semantic_views=["database_1.schema_1.arr_sv"])
        generator = SnowflakeGrantsGenerator(
            {ROLE: {"select": {"view": ["database_1.schema_1.v"]}}}, {}
        )
        config = {
            "privileges": {
                "semantic_views": {"read": ["database_1.schema_1.arr_sv"]},
            }
        }
        sql = [
            c["sql"]
            for c in generator.generate_grant_privileges_to_role(
                ROLE, config, SHARED_DBS, SPEC_DBS
            )
        ]
        assert (
            "GRANT select, references ON semantic view database_1.schema_1.arr_sv "
            "TO ROLE functional_role"
        ) in sql
        # The view grant is revoked as a view, never as a semantic view
        assert (
            "REVOKE select ON view database_1.schema_1.v FROM ROLE functional_role"
            in sql
        )


class TestSchemaWritePrivileges:
    def test_schema_write_includes_create_semantic_view(self, patch_conn):
        patch_conn()
        generator = SnowflakeGrantsGenerator({}, {})
        commands = generator.generate_schema_grants(
            ROLE, {"read": [], "write": ["database_1.schema_1"]}, SHARED_DBS, SPEC_DBS
        )
        assert (
            "GRANT usage, monitor, create table, create view, create stage, "
            "create file format, create sequence, create function, create pipe, "
            "create semantic view ON schema database_1.schema_1 TO ROLE functional_role"
        ) in [c["sql"] for c in commands]

    def test_create_semantic_view_is_revoked_when_write_dropped(self, patch_conn):
        patch_conn()
        generator = SnowflakeGrantsGenerator(
            {ROLE: {"create semantic view": {"schema": ["database_1.schema_1"]}}}, {}
        )
        commands = generator.generate_schema_grants(
            ROLE, {"read": [], "write": []}, SHARED_DBS, SPEC_DBS
        )
        assert [c["sql"] for c in commands if "REVOKE" in c["sql"]] == [
            "REVOKE monitor, create table, create view, create stage, "
            "create file format, create sequence, create function, create pipe, "
            "create semantic view ON schema database_1.schema_1 "
            "FROM ROLE functional_role"
        ]


def spec(semantic_views):
    return yaml.safe_load(
        yaml.safe_dump(
            {
                "version": "1.0",
                "databases": [{"database_1": {"shared": False}}],
                "roles": [
                    {
                        "omni": {
                            "privileges": {
                                "databases": {"read": ["database_1"]},
                                "semantic_views": semantic_views,
                            }
                        }
                    }
                ],
            }
        )
    )


class TestSemanticViewSpec:
    def test_valid_spec(self):
        s = spec({"read": ["database_1.schema_1.*", "database_1.schema_1.sv"]})
        assert ensure_valid_schema(s) == []
        entities = EntityGenerator(s).inspect_entities()
        assert entities["semantic_view_refs"] == {
            "database_1.schema_1.*",
            "database_1.schema_1.sv",
        }
        assert "database_1.schema_1" in entities["schema_refs"]

    def test_unknown_privilege_key_is_still_rejected(self):
        s = spec({"read": []})
        s["roles"][0]["omni"]["privileges"]["bogus_things"] = {"read": []}
        assert ensure_valid_schema(s) != []

    def test_bad_access_level_is_rejected(self):
        assert ensure_valid_schema(spec({"admin": ["database_1.schema_1.*"]})) != []

    def test_write_is_rejected(self):
        generator = EntityGenerator(spec({"write": ["database_1.schema_1.*"]}))
        with pytest.raises(Exception, match="semantic_views.write"):
            generator.inspect_entities()

    @pytest.mark.parametrize(
        "name", ["database_1.schema_1", "database_1.*.sv", "*.schema_1.sv"]
    )
    def test_bad_names_are_rejected(self, name):
        generator = EntityGenerator(spec({"read": [name]}))
        with pytest.raises(Exception, match="semantic view name"):
            generator.inspect_entities()

    def test_database_must_be_readable(self):
        s = spec({"read": ["database_2.schema_1.*"]})
        with pytest.raises(Exception, match="semantic view read privileges"):
            EntityGenerator(s).inspect_entities()


class TestSemanticViewConnector:
    @pytest.fixture
    def conn(self, mocker, monkeypatch):
        for key in ("USER", "PASSWORD", "ACCOUNT", "DATABASE", "ROLE", "WAREHOUSE"):
            monkeypatch.setenv(f"PERMISSION_BOT_{key}", "TEST")
        mocker.patch("sqlalchemy.create_engine")
        conn = SnowflakeConnector()
        conn.run_query = mocker.MagicMock()
        return conn

    def test_show_semantic_views(self, conn, mocker):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {
                    "database_name": "DATABASE_1",
                    "schema_name": "SCHEMA_1",
                    "name": "ARR_SV",
                },
                {
                    "database_name": "DATABASE_1",
                    "schema_name": "SCHEMA_1",
                    "name": "CaseSensitive",
                },
            ],
        )
        assert conn.show_semantic_views("database_1", "schema_1") == [
            "database_1.schema_1.arr_sv",
            'database_1.schema_1."CaseSensitive"',
        ]
        conn.run_query.assert_has_calls(
            [mocker.call("SHOW SEMANTIC VIEWS IN SCHEMA schema_1")]
        )

    @pytest.mark.parametrize("granted_on", ["SEMANTIC_VIEW", "SEMANTIC VIEW"])
    def test_grants_to_role_keys_semantic_views_apart_from_views(
        self, conn, mocker, granted_on
    ):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {
                    "privilege": "SELECT",
                    "granted_on": granted_on,
                    "name": "DATABASE_1.SCHEMA_1.ARR_SV",
                },
                {
                    "privilege": "SELECT",
                    "granted_on": "VIEW",
                    "name": "DATABASE_1.SCHEMA_1.A_VIEW",
                },
            ],
        )
        assert conn.show_grants_to_role("some_role") == {
            "select": {
                "semantic_view": ["database_1.schema_1.arr_sv"],
                "view": ["database_1.schema_1.a_view"],
            }
        }

    @pytest.mark.parametrize("future", ["<SEMANTIC_VIEW>", "<SEMANTIC VIEW>"])
    def test_future_grants_are_normalized(self, conn, mocker, future):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {
                    "grant_to": "ROLE",
                    "grantee_name": "SOME_ROLE",
                    "privilege": "SELECT",
                    "grant_on": "SEMANTIC_VIEW",
                    "name": f"DATABASE_1.SCHEMA_1.{future}",
                }
            ],
        )
        assert conn.show_future_grants(schema="database_1.schema_1") == {
            "some_role": {
                "select": {"semantic_view": ["database_1.schema_1.<semantic_view>"]}
            }
        }
