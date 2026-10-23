"""
conftest.py — Global Test Fixtures and Pipeline Initialization for CyberGuard.

Guarantees that test environment variables are established and the SQLite database
with the primary administrator and model baseline registry is deterministically bootstrapped
before any test module runs.
"""

from __future__ import annotations

import os
import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_suite_environment():
    """Ensure test environment variables and database are initialized deterministically."""
    os.environ.setdefault("CYBERGUARD_ADMIN_PASSWORD", "Admin@CyberGuard2026!")
    os.environ.setdefault("EMAIL_TEST_MODE", "true")
    os.environ.setdefault("VIRUSTOTAL_ENABLED", "true")
    os.environ.setdefault("VIRUSTOTAL_API_KEY", "ci-mock-virustotal-key-for-testing")
    os.environ.setdefault("URLHAUS_ENABLED", "true")
    os.environ.setdefault("URLHAUS_AUTH_KEY", "ci-mock-urlhaus-key-for-testing")

    from backend.storage.database import init_db
    from backend.storage.auth import bootstrap_system

    init_db("data/cyberguard.db")
    bootstrap_system()
