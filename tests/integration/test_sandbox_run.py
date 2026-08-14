"""
Live-Snowflake tests for a sandbox account.

The mocked unit suite can only assert that Permifrost behaves correctly given
assumptions about what Snowflake returns. Bugs where those assumptions are
wrong -- such as Catalog-Linked Databases quoting identifiers in SHOW GRANTS but
not in SHOW SCHEMAS (issue #252) -- are invisible to it by construction. These
tests exercise a real account instead.

Skipped unless the connection environment and PERMIFROST_INTEGRATION_SPEC are
set. See sandbox/README.md.
"""

import pytest

pytestmark = pytest.mark.integration


def test_spec_test_validates_against_live_account(permifrost, spec_path):
    """
    Every entity referenced by the spec exists on the server.
    """
    result = permifrost("spec-test", spec_path)

    assert (
        result.returncode == 0
    ), f"spec-test failed:\n{result.stdout}\n{result.stderr}"


def test_dry_run_succeeds(permifrost, spec_path):
    """
    A dry run plans successfully and executes nothing.
    """
    result = permifrost("run", spec_path, "--dry")

    assert result.returncode == 0, f"dry run failed:\n{result.stdout}\n{result.stderr}"


def test_dry_run_generates_no_revoke_for_granted_spec_entity(
    permifrost, spec_path, pending_statements
):
    """
    No object is both granted and revoked by the same plan.

    This is the shape of issue #252: an identifier that compares unequal to
    itself across two Snowflake queries gets granted and revoked on every run,
    so permissions never converge. Such a plan is always wrong regardless of
    which objects the spec covers, which makes this assertion safe to run
    against any account.
    """
    result = permifrost("run", spec_path, "--dry")
    assert result.returncode == 0, f"dry run failed:\n{result.stdout}\n{result.stderr}"

    granted = set()
    revoked = set()
    for statement in pending_statements(result.stdout):
        parts = statement.split()
        if "GRANT" in parts and "TO" in parts:
            granted.add(" ".join(parts[parts.index("ON") : parts.index("TO")]))
        elif "REVOKE" in parts and "FROM" in parts:
            revoked.add(" ".join(parts[parts.index("ON") : parts.index("FROM")]))

    assert not granted & revoked, (
        "the same objects are both granted and revoked in one plan: "
        f"{sorted(granted & revoked)}"
    )


def test_apply_converges(permifrost, spec_path, apply_allowed, pending_statements):
    """
    Applying twice is a no-op the second time.

    Convergence is the property that actually matters in production: if a
    second dry run still has work to do, Permifrost is fighting itself and
    permissions flap on every scheduled run.
    """
    if not apply_allowed:
        pytest.skip("PERMIFROST_INTEGRATION_ALLOW_APPLY not set")

    applied = permifrost("run", spec_path)
    assert applied.returncode == 0, f"apply failed:\n{applied.stdout}\n{applied.stderr}"

    replanned = permifrost("run", spec_path, "--dry")
    assert replanned.returncode == 0

    remaining = pending_statements(replanned.stdout)
    assert (
        remaining == []
    ), "account did not converge; still pending after apply:\n" + "\n".join(remaining)
