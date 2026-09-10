import os
import sys
from pathlib import Path
import pytest

# Ensure repository root is on sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Set REQUIRE_HTTPS=false at module load time BEFORE any test file imports
# src_py.config or src_py.main. Pydantic Settings reads os.environ first.
os.environ["REQUIRE_HTTPS"] = "false"

# Ensure the singleton settings instance also has require_https=False
try:
    from src_py.config import settings
    settings.require_https = False
except Exception:
    pass


@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    """Autouse session fixture to guarantee HTTPS is disabled during tests."""
    os.environ["REQUIRE_HTTPS"] = "false"
    from src_py.config import settings
    settings.require_https = False
    yield
