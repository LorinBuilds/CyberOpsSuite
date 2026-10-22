"""HTTP API for Event Log Analyzer.

Run from the repository root::

    python -m event_log_analyzer.api.main

Requires the ``api`` extra: ``pip install ".[api]"``. The API only parses text sent
in the request body; it never reads paths from the server's disk.
"""

from __future__ import annotations

import os
import sys
from typing import Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from event_log_analyzer import __version__
from event_log_analyzer.core.filters import filter_entries
from event_log_analyzer.core.parser import parse_lines

MAX_CONTENT_BYTES = 1_000_000
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

app = FastAPI(
    title="Event Log Analyzer API",
    description="Parse and filter JSON Lines log content.",
    version=__version__,
)


class ParseRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        description="Log content in JSON Lines format: one JSON object per line.",
    )
    level: Literal["ALL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"] = "ALL"
    search: str | None = None
    limit: int = Field(default=100, ge=1, le=5000)


class EventModel(BaseModel):
    timestamp: str
    level: str
    event_id: str = ""
    source: str = ""
    log_name: str = ""
    machine: str = ""
    message: str


class IssueModel(BaseModel):
    line: int
    error: str


class ParseResponse(BaseModel):
    count: int
    limit: int
    level_filter: str
    search: str | None
    events: list[EventModel]
    parse_issues: list[IssueModel]


@app.get("/health", tags=["Status"])
def health() -> dict[str, str]:
    """Return API status."""
    return {"status": "ok", "service": "event-log-analyzer", "version": __version__}


@app.post("/logs/parse", response_model=ParseResponse, tags=["Logs"])
def parse_logs(request: ParseRequest) -> ParseResponse:
    """Parse JSON Lines supplied in the request body and apply the requested filters."""
    if len(request.content.encode("utf-8")) > MAX_CONTENT_BYTES:
        raise HTTPException(status_code=413, detail="Log content exceeds 1 MB limit.")

    # Split on "\n" only: str.splitlines() would also break on characters such as U+2028
    # that are legal inside JSON strings.
    entries, issues = parse_lines(request.content.split("\n"))
    matched = filter_entries(
        entries, level=request.level, search=request.search, limit=request.limit
    )
    return ParseResponse(
        count=len(matched),
        limit=request.limit,
        level_filter=request.level,
        search=request.search,
        events=[EventModel(**entry.to_dict()) for entry in matched],
        parse_issues=[IssueModel(line=issue.line, error=issue.error) for issue in issues],
    )


def main() -> None:
    # Bind to localhost by default: the API has no authentication.
    host = os.environ.get("EVENT_LOG_API_HOST", "127.0.0.1")
    port = int(os.environ.get("EVENT_LOG_API_PORT", "8000"))
    if host not in LOOPBACK_HOSTS:
        print(
            f"WARNING: binding to {host} exposes this unauthenticated API to the network.",
            file=sys.stderr,
        )
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
