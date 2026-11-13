"""Install pinned public reference feeds before any test reads the local index.

knowledge/reference-datasets/cache/ and state/mitr3-intel.sqlite3 are generated
and gitignored. The pinned JSON in the checkout is the deterministic input.
"""
import contextlib
import importlib.util
import io
from pathlib import Path


def pytest_sessionstart(session):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "mitr3_fixture_bootstrap", root / "bin/mitr3-rag-intel.py")
    intel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(intel)
    with contextlib.redirect_stdout(io.StringIO()):
        intel.bootstrap()
