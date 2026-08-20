"""Run the bundled demonstration from a source checkout.

The demo itself lives in :mod:`bouncer.demo` so that it ships inside the wheel
and `bouncer demo` works for anyone who installed from PyPI. This shim only
exists so the file keeps working from a clone.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer.demo import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
