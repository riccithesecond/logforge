"""
pytest configuration. Sets ANTHROPIC_API_KEY in the environment so config.py
can load without a real .env file during tests.
"""
import os
import pytest


def pytest_configure(config):
    # Provide a dummy API key so Settings() can instantiate during tests.
    # Tests that validate missing-key behaviour override this in the test itself.
    if "ANTHROPIC_API_KEY" not in os.environ:
        os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
