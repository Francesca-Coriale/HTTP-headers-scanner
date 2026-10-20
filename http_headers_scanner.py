"""
©AngelaMos | 2026
"""

# Standard library: parse command-line flags like `--timeout 5` into
# a tidy object so we do not have to slice `sys.argv` by hand.
import argparse
# Standard library: regular expressions — we use `re.search` to match
# header values against rule patterns (e.g. `max-age\s*=\s*[1-9]` for
# HSTS, which must reject `max-age=0`).
import re
# Standard library: access to interpreter internals — we use it for
# stderr writes and to exit the process with a specific status code.
import sys
# Standard library: a decorator that turns a class into a small,
# immutable data record without writing `__init__` boilerplate.
from dataclasses import dataclass
# Standard library: a type hint that pins a value to a small fixed
# set of strings (here: severity levels like "good"/"warn"). Mypy
# catches typos.
from typing import Literal

# Third-party (httpx): the HTTP client that actually fetches the URL.
# Modern replacement for `requests` — supports timeouts and HTTP/2.
import httpx
# Third-party (rich): the printer that draws colored output to the
# terminal, with full Unicode and width handling.
from rich.console import Console
# Third-party (rich): draws a bordered box around content — we use
# it for the summary banner at the top of the report.
from rich.panel import Panel
# Third-party (rich): builds the colored ASCII table that lists each
# header finding with its severity.
from rich.table import Table