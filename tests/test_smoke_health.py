# Importing overlay ensures overrides are applied before we grab the app
from overlay import main_override  # noqa: F401
from overlay.main_override import health


def test_health_ok():
    assert health() == {"status": "ok"}

