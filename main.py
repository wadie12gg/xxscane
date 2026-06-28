"""Compatibility shim.

The tool is now a package (`xsscane`). After `pip install -e .` you can still run
`python main.py ...`, but the canonical invocations are the installed `xsscane`
command or `python -m xsscane`.
"""

import sys

from xsscane.cli import main

if __name__ == "__main__":
    sys.exit(main())
