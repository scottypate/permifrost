# Sandbox integration testing

Permifrost's unit suite runs entirely against `MockSnowflakeConnector`. That
suite can only check that Permifrost behaves correctly *given assumptions about
what Snowflake returns* — so any bug where those assumptions are wrong is
invisible to it.

Issue [#252](https://gitlab.com/gitlab-data/permifrost/-/issues/252) is the
canonical example: Catalog-Linked Databases return
`atlan_context_store."entity_history"` from `SHOW GRANTS` but
`atlan_context_store.entity_history` from `SHOW SCHEMAS`. Permifrost granted and
then immediately revoked the same schema on every run. No mock could have caught
it, because the mocks encoded the same wrong assumption as the code.

This directory holds the spec for a throwaway Snowflake account that the
integration suite runs against.

## What the suite checks

`tests/integration/test_sandbox_run.py`:

| Test | Mutates account | What it protects |
|---|---|---|
| `test_spec_test_validates_against_live_account` | no | Every entity in the spec exists on the server |
| `test_dry_run_succeeds` | no | A plan can be generated without error |
| `test_dry_run_generates_no_revoke_for_granted_spec_entity` | no | No object is granted and revoked by the same plan — the #252 signature |
| `test_apply_converges` | **yes** | A second run is a no-op; permissions do not flap |

`test_apply_converges` is the highest-value one. Convergence is what actually
matters in production: if a second dry run still has work to do, Permifrost is
fighting itself. It only runs when `PERMIFROST_INTEGRATION_ALLOW_APPLY` is set.

## Local use

The whole suite skips unless it is fully configured, and tells you what is
missing:

```
$ pytest -m integration -rs
SKIPPED [4] integration suite unavailable (unset connection variables:
PERMISSION_BOT_USER, ...; PERMIFROST_INTEGRATION_SPEC not set)
```

To run it:

```bash
export PERMISSION_BOT_ACCOUNT=YS68254-GITLAB_SANDBOX
export PERMISSION_BOT_USER=PERMIFROST_CI
export PERMISSION_BOT_ROLE=PERMIFROST_CI_ROLE
export PERMISSION_BOT_WAREHOUSE=PERMIFROST_CI_XS
export PERMISSION_BOT_DATABASE=<any database the role can use>
export PERMISSION_BOT_KEY_PATH=~/.ssh/permifrost_ci_key.p8
export PERMIFROST_INTEGRATION_SPEC=sandbox/snowflake_spec.yml

pytest -v -m integration                      # read-only checks
PERMIFROST_INTEGRATION_ALLOW_APPLY=true \
  pytest -v -m integration                    # includes the apply
```

Use the pinned tool versions from `requirements.txt`; `setup.py` pins nothing and
the repo does not work with current pytest. See `CONTRIBUTING.md`.

## CI

`.gitlab/ci/sandbox.gitlab-ci.yml` adds an `integration-test` stage:

- `sandbox_spec_test` — read-only, runs on every branch
- `sandbox_apply` — `when: manual`, master only, mutates the account

Both jobs are omitted from the pipeline entirely while `PERMISSION_BOT_ACCOUNT`
is unset, so this costs nothing until the service account exists.

Required CI/CD variables (all masked; **protected** for the key):

| Variable | Type | Notes |
|---|---|---|
| `PERMISSION_BOT_ACCOUNT` | var | Also acts as the on/off switch for the stage |
| `PERMISSION_BOT_USER` | var | |
| `PERMISSION_BOT_ROLE` | var | Must hold `SECURITYADMIN`-equivalent grants |
| `PERMISSION_BOT_WAREHOUSE` | var | |
| `PERMISSION_BOT_DATABASE` | var | |
| `PERMISSION_BOT_KEY` | **file** | Private key contents; GitLab exposes file variables as a path, which `PERMISSION_BOT_KEY_PATH` points at |

Use key pair auth, not a password — the CI user should be passwordless.

## Setup not yet done

`snowflake_spec.yml` is a placeholder. Before these tests do anything useful:

1. **Create the service account** in the sandbox: `PERMIFROST_CI_ROLE`,
   `PERMIFROST_CI` (key pair auth), `PERMIFROST_CI_XS` (X-Small,
   `auto_suspend=60`).
2. **Inventory the sandbox account** — databases, warehouses, roles, users.
3. **Write the spec from that inventory.** It has to describe the account
   accurately or `spec-test` fails on entities that do not exist. Aim to cover
   the features most likely to regress: wildcards, ownership, future grants,
   `member_of`, and — given #252 — at least one Catalog-Linked / Iceberg
   database with a genuinely lowercase schema name.

Step 3 is where the value is. A spec that only covers ordinary uppercase
databases will pass happily while the interesting bugs go undetected.
