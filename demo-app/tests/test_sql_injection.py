import pytest


@pytest.mark.skip(reason="Enable after Attack2Patch applies the safe patch to the isolated demo app")
def test_sql_injection_is_blocked_after_patch():
    """Acceptance-test placeholder for the post-patch image."""
