"""Launcher used by action.yml.

Run as ``python3 -I run.py ...``. Isolated mode ignores PYTHON* environment variables, the user
site directory and the current directory, so a pull request cannot shadow prscreen's modules by
adding a ``prscreen/`` folder to the repository being scanned. Only this file's own ``src/`` is
put on the import path.
"""

import sys
from pathlib import Path

if sys.version_info < (3, 12):  # noqa: UP036 - a runner's python3 may be older than ours
    sys.stdout.write(
        "::error title=prscreen::Python 3.12 or newer is required; "
        f"found {sys.version.split()[0]}. Add actions/setup-python before this step.\n"
    )
    raise SystemExit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from prscreen.cli import main

raise SystemExit(main(sys.argv[1:]))
