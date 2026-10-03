"""Pytest configuration and test lifecycle fixtures."""

import pytest
from backend.app.core.limiter import limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter_fixture():
    """Ensure that every test starts and ends with clean, reset rate limiter storage.
    
    This guarantees that unit and integration tests do not cross-pollinate rate limit
    quotas or cause false-positive 429 errors during test execution.
    """
    limiter.reset()
    yield
    limiter.reset()
