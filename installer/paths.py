"""One resource root, equally valid in a checkout or a verified release archive."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESOURCES = PROJECT_ROOT / "resources"
