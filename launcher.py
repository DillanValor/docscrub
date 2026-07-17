"""Frozen-app entry point.

Double-clicking the built app (no arguments) launches the GUI.
The CLI still works from a terminal:  ./DocScrub sanitize ticket.docx
"""

import multiprocessing
import sys

from docscrub.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    argv = sys.argv[1:] if len(sys.argv) > 1 else ["gui"]
    sys.exit(main(argv))
