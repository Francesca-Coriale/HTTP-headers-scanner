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

#Literal type hints for severity and status values. Mypy will catch typos.
Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]

#'frozen=True' makes the dataclass immutable, so we cannot accidentally
# change a rule after it is created. 'slots=True' saves memory by
# storing attributes in a fixed-size array instead of a dict.
@dataclass(frozen=True, slots=True)
class HeaderRule:
    """
    A rule that describes a single HTTP header and how to evaluate it.
    """
    header: str
    severity: Severity
    description: str
    recommendation: str
#'must_match': optional regex pattern that the header value MUST match. 
# if it is set, and the value does not match, we report 'weak'. 
# if None, any value is accepted.
    must_match: str | None = None

RULES: list[HeaderRule] = [
    HeaderRule(
        header = "Strict-Transport-Security",
        severity = "high",
        description = (
            "Tells the browser to ONLY connect over HTTPS for the "
            "next N seconds, defeating SSL-stripping attacks."
        ),
        recommendation = (
            "Add: Strict-Transport-Security: "
            "max-age=31536000; includeSubDomains"
        ),
        # require max-age to be a positive integer 
        # 'max-age=0' disables HSTS, so we reject it. 
        # we also allow whitespace around the '='.
        must_match = r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header = "Content-Security-Policy",
        severity = "high",
        description = (
            "Controls which scripts, styles, frames, and connections "
            "the browser may load. It is the strongest XSS defense."
        ),
        recommendation = (
            "Add: Content-Security-Policy that disallows "
            "'unasfe-inline' and limits sources to trusted origins."
        ),
    ),
    HeaderRule(
        header = "X-Content-Type-Options",
        severity = "medium",
        description = (
            "Prevents the browser from second-guessing the Content-Type "
            "and treating a .txt file as HTML. It defeats MIME-sniffing."
        ),
        recommendation = "Add: X-Content-Type-Options: nosniff",
        must_match = "nosniff",
    ),
    HeaderRule(
        header = "Referrer-Policy",
        severity = "low",
        description = (
            "Limits how much the current URL leaks to other sites "
            "when the user clicks an outbound link."
        ),
        recommendation = (
            "Add: Referrer-Policy: strict-origin-when-cross-origin."
        ),
    ),
    HeaderRule(
        header = "Permissions-Policy",
        severity = "low",
        description = (
            "Disables browser features the page does not use "
            "(camera, microphone, geolocation, payments, etc.)."
        ),
        recommendation = (
            "Add: Permissions-Policy: "
            "camera=(), microphone=(), geolocation=()"
        ),
    ),
]