"""
Shared gating for the live-Snowflake integration suite.

Every test here needs a real Snowflake account, so the whole suite skips unless
the connection environment is present and PERMIFROST_INTEGRATION_SPEC points at
a spec file describing that account. This keeps `pytest` green for contributors
and forks with no credentials, which is the default case.
"""

import os
import subprocess
import sys

import pytest

CONNECTION_VARS = (
    "PERMISSION_BOT_USER",
    "PERMISSION_BOT_ACCOUNT",
    "PERMISSION_BOT_WAREHOUSE",
    "PERMISSION_BOT_DATABASE",
    "PERMISSION_BOT_ROLE",
)

# One of these must be set for the connector to authenticate at all.
CREDENTIAL_VARS = (
    "PERMISSION_BOT_KEY_PATH",
    "PERMISSION_BOT_PASSWORD",
    "PERMISSION_BOT_OAUTH_TOKEN",
)

SPEC_VAR = "PERMIFROST_INTEGRATION_SPEC"
ALLOW_APPLY_VAR = "PERMIFROST_INTEGRATION_ALLOW_APPLY"


def missing_requirements():
    """Return the reasons this suite cannot run, empty if it can."""
    reasons = []

    unset = [name for name in CONNECTION_VARS if not os.getenv(name)]
    if unset:
        reasons.append(f"unset connection variables: {', '.join(unset)}")

    if not any(os.getenv(name) for name in CREDENTIAL_VARS):
        reasons.append(f"no credential in any of {', '.join(CREDENTIAL_VARS)}")

    spec_path = os.getenv(SPEC_VAR)
    if not spec_path:
        reasons.append(f"{SPEC_VAR} not set")
    elif not os.path.isfile(spec_path):
        reasons.append(f"{SPEC_VAR} does not point at a file: {spec_path}")

    return reasons


def pytest_collection_modifyitems(config, items):
    reasons = missing_requirements()
    if not reasons:
        return

    skip = pytest.mark.skip(
        reason=f"integration suite unavailable ({'; '.join(reasons)})"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def spec_path():
    return os.environ[SPEC_VAR]


@pytest.fixture(scope="session")
def apply_allowed():
    """
    Applying mutates the target account, so it stays opt-in even when
    credentials are present.
    """
    return os.getenv(ALLOW_APPLY_VAR, "").lower() in ("1", "true", "yes")


@pytest.fixture(scope="session")
def permifrost():
    """
    Invoke the installed CLI the way CI and operators do, rather than calling
    into the package, so exit codes and the packaged entry point are covered.
    """

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "permifrost.cli", *args],
            capture_output=True,
            text=True,
            check=False,
        )

    return run


@pytest.fixture(scope="session")
def pending_statements():
    """
    Extract the statements Permifrost would execute from `run --dry` output.

    `print_command` prefixes these with [PENDING]; anything already in place is
    either omitted or printed as [SKIPPED].
    """

    def extract(output):
        return [line.strip() for line in output.splitlines() if "[PENDING]" in line]

    return extract
