"""Ensure the backend directory is importable as the top-level `app` package."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
