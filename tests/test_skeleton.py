"""Smoke test validating system structure and imports for Phase 1."""

import os
import pytest


def test_directory_structure_exists():
    """Ensure all required Phase 1 top-level directories exist."""
    required_dirs = [
        "backend",
        "frontend",
        "machine-learning",
        "datasets",
        "database",
        "tests",
        "documentation",
        "configuration",
    ]
    for d in required_dirs:
        assert os.path.isdir(d), f"Required directory '{d}' is missing!"


def test_backend_entrypoint_imports():
    """Ensure backend main application can be imported without errors."""
    from backend.app.main import app
    assert app is not None
    assert app.title == "AI Network Intrusion Detection System"
