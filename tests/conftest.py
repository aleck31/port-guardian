"""Make `chalicelib` importable — it lives under app/, which is the Chalice root."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'app'))
