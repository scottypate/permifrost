import pytest
import yaml

from permifrost.entities import EntityGenerator
from permifrost.error import SpecLoadingError
from permifrost.snowflake_connector import SnowflakeConnector
from permifrost.snowflake_grants import SnowflakeGrantsGenerator
from permifrost.snowflake_spec_loader import SnowflakeSpecLoader
from permifrost.spec_file_loader import ensure_valid_schema

ROLE = "ar_dbr_snowflake_cortex_user"
CORTEX_USER = "snowflake.cortex_user"
GRANT = f"GRANT DATABASE ROLE {CORTEX_USER} TO ROLE {ROLE}"
REVOKE = f"REVOKE DATABASE ROLE {CORTEX_USER} FROM ROLE {ROLE}"


@pytest.fixture(autouse=True)
def no_connection(mocker):
    """The grants generator builds a SnowflakeConnector; never connect."""
    mocker.patch.object(SnowflakeConnector, "__init__", lambda x: None)


def held(*database_roles, role=ROLE):
    return {role: {"usage": {"database_role": list(database_roles)}}}


def database_role_sql(grants_to_role, config, role=ROLE, only_new=True):
    generator = SnowflakeGrantsGenerator(grants_to_role, {})
    commands = generator.generate_grant_roles("roles", role, config)
    return [
        c["sql"]
        for c in commands
        if "DATABASE ROLE" in c["sql"] and not (only_new and c["already_granted"])
    ]


class TestDatabaseRoleGrants:
    def test_declared_and_not_held_is_granted(self):
        assert database_role_sql({}, {"database_roles": [CORTEX_USER]}) == [GRANT]

    def test_already_held_is_flagged_and_nothing_new(self):
        generator = SnowflakeGrantsGenerator(held(CORTEX_USER), {})
        commands = generator.generate_grant_roles(
            "roles", ROLE, {"database_roles": [CORTEX_USER]}
        )
        assert commands == [{"already_granted": True, "sql": GRANT}]
        assert (
            database_role_sql(held(CORTEX_USER), {"database_roles": [CORTEX_USER]})
            == []
        )

    def test_undeclared_held_is_revoked(self):
        grants = held(CORTEX_USER, "snowflake.copilot_user")
        assert database_role_sql(grants, {"database_roles": [CORTEX_USER]}) == [
            f"REVOKE DATABASE ROLE snowflake.copilot_user FROM ROLE {ROLE}"
        ]

    def test_revoke_applies_in_any_database(self):
        grants = held("other_db.some_role")
        assert database_role_sql(grants, {"database_roles": []}) == [
            f"REVOKE DATABASE ROLE other_db.some_role FROM ROLE {ROLE}"
        ]

    def test_missing_key_is_empty_list_and_revokes_all_held(self):
        grants = held(CORTEX_USER, "snowflake.copilot_user")
        assert database_role_sql(grants, {}) == [
            REVOKE,
            f"REVOKE DATABASE ROLE snowflake.copilot_user FROM ROLE {ROLE}",
        ]
        assert database_role_sql(grants, {"database_roles": []}) == database_role_sql(
            grants, {}
        )

    def test_role_with_no_database_roles_and_none_held_is_silent(self):
        assert database_role_sql({}, {"member_of": ["ar_x"]}) == []

    def test_other_roles_grants_are_not_touched(self):
        grants = held(CORTEX_USER, role="someone_else")
        assert database_role_sql(grants, {"database_roles": []}) == []

    def test_database_role_rows_never_become_revoke_role(self):
        grants = {
            ROLE: {
                "usage": {"database_role": [CORTEX_USER], "role": ["ar_x"]},
            }
        }
        generator = SnowflakeGrantsGenerator(grants, {})
        sql = [
            c["sql"]
            for c in generator.generate_grant_roles(
                "roles", ROLE, {"member_of": ["ar_x"], "database_roles": []}
            )
        ]
        assert sql == [f"GRANT ROLE ar_x TO role {ROLE}", REVOKE]
        assert not [s for s in sql if s.startswith("REVOKE ROLE")]

    def test_role_rows_never_become_revoke_database_role(self):
        grants = {ROLE: {"usage": {"role": ["ar_x"]}}}
        generator = SnowflakeGrantsGenerator(grants, {})
        sql = [
            c["sql"]
            for c in generator.generate_grant_roles(
                "roles", ROLE, {"member_of": [], "database_roles": []}
            )
        ]
        assert sql == [f"REVOKE ROLE ar_x FROM role {ROLE}"]

    def test_database_role_statements_come_after_member_of(self):
        grants = {ROLE: {"usage": {"database_role": [CORTEX_USER], "role": ["ar_y"]}}}
        generator = SnowflakeGrantsGenerator(grants, {})
        sql = [
            c["sql"]
            for c in generator.generate_grant_roles(
                "roles", ROLE, {"member_of": ["ar_x"]}
            )
        ]
        assert sql.index(f"GRANT ROLE ar_x TO role {ROLE}") < sql.index(REVOKE)
        assert sql.index(f"REVOKE ROLE ar_y FROM role {ROLE}") < sql.index(REVOKE)

    def test_ignore_memberships_skips_database_roles(self):
        generator = SnowflakeGrantsGenerator(
            held(CORTEX_USER, "snowflake.copilot_user"), {}, ignore_memberships=True
        )
        assert (
            generator.generate_grant_roles(
                "roles", ROLE, {"database_roles": ["snowflake.other"]}
            )
            == []
        )

    def test_users_are_never_given_database_role_statements(self):
        generator = SnowflakeGrantsGenerator({}, {"some_user": []})
        sql = [
            c["sql"]
            for c in generator.generate_grant_roles(
                "users", "some_user", {"member_of": []}
            )
        ]
        assert sql == []

    @pytest.mark.parametrize(
        "held_name",
        [
            'snowflake."CORTEX-MODEL-ROLE-ALL"',
        ],
    )
    def test_quoted_names_match_exact_case(self, held_name):
        config = {"database_roles": ['snowflake."CORTEX-MODEL-ROLE-ALL"']}
        generator = SnowflakeGrantsGenerator(held(held_name), {})
        commands = generator.generate_grant_roles("roles", ROLE, config)
        assert commands == [
            {
                "already_granted": True,
                "sql": 'GRANT DATABASE ROLE snowflake."CORTEX-MODEL-ROLE-ALL" '
                f"TO ROLE {ROLE}",
            }
        ]

    def test_quoted_name_in_wrong_case_does_not_match(self):
        grants = held('snowflake."CORTEX-MODEL-ROLE-ALL"')
        config = {"database_roles": ['snowflake."cortex-model-role-all"']}
        assert database_role_sql(grants, config) == [
            'GRANT DATABASE ROLE snowflake."cortex-model-role-all" ' f"TO ROLE {ROLE}",
            'REVOKE DATABASE ROLE snowflake."CORTEX-MODEL-ROLE-ALL" '
            f"FROM ROLE {ROLE}",
        ]

    def test_unquoted_spec_name_needing_quotes_matches_quoted_show_row(self):
        grants = held('snowflake."CORTEX-MODEL-ROLE-ALL"')
        config = {"database_roles": ["snowflake.CORTEX-MODEL-ROLE-ALL"]}
        assert database_role_sql(grants, config) == []

    def test_grantee_with_special_characters_is_quoted(self):
        sql = database_role_sql({}, {"database_roles": [CORTEX_USER]}, role="ar-x")
        assert sql == ['GRANT DATABASE ROLE snowflake.cortex_user TO ROLE "ar-x"']


def build_loader(mocker, spec, grants_to_role):
    mocker.patch.object(SnowflakeSpecLoader, "__init__", lambda *args: None)
    loader = SnowflakeSpecLoader("", None)
    loader.spec = spec
    loader.entities = EntityGenerator(spec).inspect_entities()
    loader.grants_to_role = grants_to_role
    loader.roles_granted_to_user = {}
    return loader


def roles_spec(**roles):
    return yaml.safe_load(
        yaml.safe_dump(
            {
                "version": "1.0",
                "roles": [{name: config} for name, config in roles.items()],
            }
        )
    )


class TestDatabaseRolesThroughSpecLoader:
    def test_referenced_only_and_undeclared_roles_are_never_touched(self, mocker):
        spec = roles_spec(
            **{
                ROLE: {"database_roles": [CORTEX_USER]},
                "ar_other": {"member_of": ["accountadmin"]},
            }
        )
        grants = {
            # referenced only (member_of target), not declared
            "accountadmin": {"usage": {"database_role": [CORTEX_USER]}},
            # neither declared nor referenced
            "public": {"usage": {"database_role": [CORTEX_USER]}},
        }
        queries = build_loader(mocker, spec, grants).generate_permission_queries()
        sql = [q["sql"] for q in queries]
        assert GRANT in sql
        assert not [s for s in sql if "accountadmin" in s and "DATABASE ROLE" in s]
        assert not [s for s in sql if "public" in s]
        assert [s for s in sql if "DATABASE ROLE" in s] == [GRANT]

    def test_old_spec_without_database_roles_now_revokes_held_ones(self, mocker):
        """BREAKING: absent key == [], so held database roles are revoked."""
        spec = roles_spec(ar_plain={"member_of": ["ar_x"]}, ar_x={"member_of": []})
        grants = {"ar_plain": {"usage": {"database_role": [CORTEX_USER]}}}
        queries = build_loader(mocker, spec, grants).generate_permission_queries()
        assert {
            "already_granted": False,
            "sql": "REVOKE DATABASE ROLE snowflake.cortex_user FROM ROLE ar_plain",
        } in queries

    def test_role_filter_limits_database_role_statements(self, mocker):
        spec = roles_spec(
            ar_a={"database_roles": [CORTEX_USER]},
            ar_b={"database_roles": [CORTEX_USER]},
        )
        queries = build_loader(mocker, spec, {}).generate_permission_queries(
            roles=["ar_a"]
        )
        assert [q["sql"] for q in queries] == [
            "GRANT DATABASE ROLE snowflake.cortex_user TO ROLE ar_a"
        ]

    @pytest.mark.parametrize(
        "grant_on, filter_set, expected",
        [
            # kept even though `snowflake` is not a spec database
            ("database_role", [CORTEX_USER, "other_db.r"], [CORTEX_USER, "other_db.r"]),
            # other types are still filtered to spec databases
            ("role", ["ar_x"], ["ar_x"]),
            ("table", ["snowflake.s.t"], []),
            ("schema", ["snowflake.s"], []),
            ("database", ["snowflake"], []),
        ],
    )
    def test_filter_to_database_refs(self, mocker, grant_on, filter_set, expected):
        loader = build_loader(mocker, roles_spec(ar_x={"member_of": []}), {})
        assert (
            loader.filter_to_database_refs(grant_on=grant_on, filter_set=filter_set)
            == expected
        )

    def test_database_role_rows_for_a_spec_database_are_kept_too(self, mocker):
        spec = {
            "version": "1.0",
            "databases": [{"analytics": {"shared": False}}],
            "roles": [{"ar_x": {"privileges": {"databases": {"read": ["analytics"]}}}}],
        }
        loader = build_loader(mocker, spec, {})
        assert loader.filter_to_database_refs("database_role", ["analytics.r"]) == [
            "analytics.r"
        ]


class TestCheckDatabaseRoleEntities:
    @pytest.fixture
    def loader(self, mocker):
        spec = roles_spec(
            **{ROLE: {"database_roles": [CORTEX_USER, "snowflake.copilot_user"]}}
        )
        return build_loader(mocker, spec, {})

    def test_passes_when_all_exist(self, loader, mocker):
        conn = mocker.MagicMock()
        conn.show_database_roles.return_value = [CORTEX_USER, "snowflake.copilot_user"]
        assert loader.check_database_role_entities(conn) == []
        conn.show_database_roles.assert_called_once_with("snowflake")

    def test_errors_for_missing_database_role(self, loader, mocker):
        conn = mocker.MagicMock()
        conn.show_database_roles.return_value = [CORTEX_USER]
        assert loader.check_database_role_entities(conn) == [
            "Missing Entity Error: Database role snowflake.copilot_user "
            "was not found on Snowflake Server."
        ]

    def test_errors_when_show_raises(self, loader, mocker):
        conn = mocker.MagicMock()
        conn.show_database_roles.side_effect = Exception("insufficient privileges")
        assert loader.check_database_role_entities(conn) == [
            "Missing Entity Error: database roles in snowflake "
            "not visible to securityadmin: insufficient privileges"
        ]

    def test_quoted_names_are_compared_through_snowflaky(self, mocker):
        spec = roles_spec(
            **{ROLE: {"database_roles": ['snowflake."CORTEX-MODEL-ROLE-ALL"']}}
        )
        conn = mocker.MagicMock()
        conn.show_database_roles.return_value = ['snowflake."CORTEX-MODEL-ROLE-ALL"']
        assert build_loader(mocker, spec, {}).check_database_role_entities(conn) == []

    def test_no_show_when_spec_has_no_database_roles(self, mocker):
        conn = mocker.MagicMock()
        loader = build_loader(mocker, roles_spec(ar_x={"member_of": []}), {})
        assert loader.check_database_role_entities(conn) == []
        conn.show_database_roles.assert_not_called()

    def test_failure_is_wired_into_the_entity_check(self, loader, mocker):
        for name in (
            "check_warehouse_entities",
            "check_integration_entities",
            "check_database_entities",
            "check_schema_ref_entities",
            "check_table_ref_entities",
            "check_semantic_view_ref_entities",
            "check_role_entities",
            "check_users_entities",
        ):
            mocker.patch.object(loader, name, return_value=[])
        conn = mocker.MagicMock()
        conn.show_database_roles.return_value = []
        with pytest.raises(SpecLoadingError, match="Database role snowflake.cortex"):
            loader.check_entities_on_snowflake_server(conn)


def spec_with_role(config, user=None):
    spec = {"version": "1.0", "roles": [{"ar_x": config}]}
    if user is not None:
        spec["users"] = [{"some_user": user}]
    return spec


class TestDatabaseRolesSpec:
    def test_list_of_strings_is_accepted(self):
        assert (
            ensure_valid_schema(spec_with_role({"database_roles": [CORTEX_USER]})) == []
        )
        assert ensure_valid_schema(spec_with_role({"database_roles": []})) == []

    @pytest.mark.parametrize("value", [CORTEX_USER, {"snowflake": "cortex_user"}, 1])
    def test_non_list_is_rejected(self, value):
        assert ensure_valid_schema(spec_with_role({"database_roles": value})) != []

    def test_list_of_non_strings_is_rejected(self):
        assert ensure_valid_schema(spec_with_role({"database_roles": [1]})) != []

    def test_key_under_users_is_rejected(self):
        user = {"can_login": False, "database_roles": [CORTEX_USER]}
        assert ensure_valid_schema(spec_with_role({}, user=user)) != []

    def test_entities_collect_database_roles_without_defining_the_database(self):
        entities = EntityGenerator(
            spec_with_role({"database_roles": [CORTEX_USER]})
        ).inspect_entities()
        assert entities["database_role_refs"] == {CORTEX_USER}
        assert "snowflake" not in entities["database_refs"]
        assert "snowflake" not in entities["databases"]

    @pytest.mark.parametrize(
        "name",
        ["cortex_user", "a.b.c", "snowflake.*", "*.cortex_user", "snowflake.cx_*"],
    )
    def test_bad_names_are_rejected(self, name):
        generator = EntityGenerator(spec_with_role({"database_roles": [name]}))
        with pytest.raises(
            SpecLoadingError,
            match=rf"Not a valid database role name: {name.replace('*', r'\*')}"
            r" \(Proper definition: DB.DATABASE_ROLE\)",
        ):
            generator.inspect_entities()


class TestDatabaseRolesConnector:
    @pytest.fixture
    def conn(self, mocker):
        # __init__ is patched by the autouse fixture; no engine is needed
        conn = SnowflakeConnector()
        conn.run_query = mocker.MagicMock()
        return conn

    def test_grants_to_role_keys_database_roles_apart_from_roles(self, conn, mocker):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {
                    "privilege": "USAGE",
                    "granted_on": "DATABASE_ROLE",
                    "name": "SNOWFLAKE.CORTEX_USER",
                },
                {"privilege": "USAGE", "granted_on": "ROLE", "name": "AR_X"},
            ],
        )
        assert conn.show_grants_to_role("some_role") == {
            "usage": {"database_role": ["snowflake.cortex_user"], "role": ["ar_x"]}
        }

    @pytest.mark.parametrize(
        "granted_on", ["DATABASE ROLE", "DATABASE_ROLE", "database role"]
    )
    def test_normalize_granted_on(self, granted_on):
        assert SnowflakeConnector.normalize_granted_on(granted_on) == "database_role"

    def test_normalize_granted_on_leaves_other_types_alone(self):
        assert SnowflakeConnector.normalize_granted_on("ROLE") == "role"
        assert SnowflakeConnector.normalize_granted_on("DATABASE") == "database"

    def test_show_database_roles(self, conn, mocker):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {"name": "CORTEX_USER"},
                {"name": "CORTEX-MODEL-ROLE-ALL"},
            ],
        )
        assert conn.show_database_roles("snowflake") == [
            "snowflake.cortex_user",
            'snowflake."CORTEX-MODEL-ROLE-ALL"',
        ]
        conn.run_query.assert_has_calls(
            [mocker.call("SHOW DATABASE ROLES IN DATABASE snowflake")]
        )

    @pytest.mark.parametrize(
        "row_name",
        ['SNOWFLAKE."CORTEX-MODEL-ROLE-ALL"', "SNOWFLAKE.CORTEX-MODEL-ROLE-ALL"],
    )
    def test_quoted_show_rows_normalize_to_the_spec_form(self, conn, mocker, row_name):
        mocker.patch.object(
            conn.run_query(),
            "fetchall",
            return_value=[
                {"privilege": "USAGE", "granted_on": "DATABASE_ROLE", "name": row_name}
            ],
        )
        assert conn.show_grants_to_role("some_role") == {
            "usage": {"database_role": ['snowflake."CORTEX-MODEL-ROLE-ALL"']}
        }
