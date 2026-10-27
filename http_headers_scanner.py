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

# The list of rules that we will check against the HTTP headers.
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

# Each present-and-correct header is worth full points. 
# Each weak header is worth half points. 
# Each missing header is worth 0 points.
# Tot achievable = sum of all rule points. The score is (earned/total)*100, rounded.
SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}

@dataclass(frozen=True, slots=True)
class HeaderFinding:
    """
    Outcome of running one HeaderRule against the response headers.
    """
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str

@dataclass(frozen=True, slots=True)
class ScanReport:
    """
    A full scan result for one URL
    """
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        """
        Return a 0-100 score reflecting the weighted findings.
        """
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2
            # missing headers earn 0 points

        # round-half-up via int(x+o.5) trick, 
        # since Python's round() uses "banker's rounding" 
        # which would map round(0.5)->0
        return int(round(earned/total)*100+0.5)

    @property
    def grade(self) -> str:
        """
        Map the score to a letter grade A-F.
        """
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str,
                           str],
) -> HeaderFinding:
    """
    Apply a single HeaderRule to a set of response headers

    HTTP header names are case-insensitive per RFC 7230 — `HSTS` and
    `hsts` and `Hsts` are the same header. We normalize both sides
    to lowercase before comparing
    """
    target = rule.header.lower()

    # Walk the response headers manually instead of building a
    # case-insensitive dict. The input is always a plain dict here —
    # scan() converts httpx's Headers object before calling us, so
    # tests can pass any dict[str, str] without ceremony
    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break
    
    if actual_value is None:
        return HeaderFinding(
            rule = rule,
            status = "missing",
            actual_value = None,
            note = f"Header `{rule.header}` is not set",
        )

    # If the rule has no must_match check, presence is enough
    if rule.must_match is None:
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = "Present",
        )

    # Otherwise verify the value matches the required pattern.
    # re.search finds the pattern anywhere in the string — for a plain
    # word like `nosniff` that behaves as a substring check; for a
    # real regex like `max-age\s*=\s*[1-9]` it enforces a richer
    # condition (positive integer after `max-age=`)
    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule = rule,
        status = "weak",
        actual_value = actual_value,
        note = (
            f"Present but does not match `{rule.must_match}` "
            f"(got `{actual_value}`)"
        ),
    )

# =============================================================================
# scan() — fetch the URL and apply every rule
# =============================================================================
# A polite, identifiable User-Agent. Some servers block requests with
# the default httpx UA or no UA at all
DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/CarterPerez-dev/Cybersecurity-Projects)"
)

def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    """
    Fetch the URL and apply every HeaderRule to the response headers.

    Returns a ScanReport with the findings.
    """
     # follow_redirects=True means http://example.com → https://example.com
    # is followed automatically. We grade the FINAL URL, not the first
    # one, because that is the one users actually see
    response = httpx.get(
        url,
        timeout = timeout,
        follow_redirects = True,
        headers = {"User-Agent": user_agent},
    )

    # httpx Headers object behaves like a dict for our purposes.
    # dict(response.headers) gives us a regular dict[str, str]
    response_headers = dict(response.headers)

    # Run every rule against the response. List comprehension is
    # cleaner than a for-loop with .append() here
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url = url,
        final_url = str(response.url),
        status_code = response.status_code,
        findings = findings,
    )