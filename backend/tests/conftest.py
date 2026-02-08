import sys
import os

import pytest

# Add backend directory to path so `src` is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
