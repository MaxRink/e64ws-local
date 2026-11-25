"""Test package for the offline e64root suite.

The tests are runnable both as top-level modules (``unittest discover``) and as
``tools.e64root.tests.*`` modules.  Add the tests directory and the ``tools``
directory to ``sys.path`` so the shared helpers and the package import resolve in
both modes.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent
for candidate in (str(HERE), str(TOOLS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)
