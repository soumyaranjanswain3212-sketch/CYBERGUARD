from __future__ import annotations

import hashlib
import hmac
import os
from datetime import UTC, datetime
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import storage
from .analyzer import analyze_event

app = FastAPI(
    title="CyberGuard Threat Analysis API",
    description="Analyze and persist security events for an authorized local deployment.",
    version="1.2.0",
)

origins = os.getenv(
    "CYBERGUARD_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in origins if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    source: str = Field(default="email", min_length=1, max_length=30)
    content: str = Field(default="", max_length=10_000)
    sender: str | None = Field(default=None, max_length=320)
    url: str | None = Field(default=None, max_length=2_048)
    failed_attempts: int | None = Field(default=None, ge=0, le=100_000)
    new_device: bool = False
    unusual_location: bool = False
    requests_per_minute: int | None = Field(default=None, ge=0, le=10_000_000)
    baseline_requests_per_minute: int | None = Field(default=None, gt=0, le=10_000_000)
    bytes_out_mb: float | None = Field(default=None, ge=0, le=1_000_000_000)
    baseline_bytes_out_mb: float | None = Field(default=None, gt=0, le=1_000_000_000)
    error_rate_percent: float | None = Field(default=None, ge=0, le=100)


class TelemetryIngestRequest(AnalyzeRequest):
    model_config = ConfigDict(extra="forbid")

    source: Literal["auth", "email", "identity", "network", "url"]
    source_name: str = Field(min_length=1, max_length=80)
    source_event_id: str = Field(min_length=1, max_length=200)
    observed_at: datetime

    @field_validator("source_name", "source_event_id")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Value must not be blank.")
        return normalized

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone.")
        return value.astimezone(UTC)


class StatusUpdate(BaseModel):
    status: Literal["New", "Investigating", "Contained", "Resolved"]


@app.on_event("startup")
def initialize_storage() -> None:
    storage.initialize()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "storage": "sqlite", "engine": "transparent-rule-based"}


@app.get("/api/events")
def get_events(limit: int = 500, offset: int = 0) -> list[dict]:
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(status_code=422, detail="Limit must be 1–1000 and offset cannot be negative.")
    return storage.list_events(limit=limit, offset=offset)


@app.get("/api/summary")
def get_summary() -> dict:
    return storage.get_summary()


@app.patch("/api/events/{event_id}")
def update_event(event_id: str, request: StatusUpdate) -> dict:
    event = storage.update_status(event_id, request.status)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found.")
    return event


def _validate_analysis_input(request: AnalyzeRequest) -> None:
    source = request.source.casefold()
    if source == "network":
        if request.requests_per_minute is None and request.bytes_out_mb is None and request.error_rate_percent is None:
            raise HTTPException(
                status_code=422,
                detail="Provide request volume, outbound data, or API error-rate measurements.",
            )
        if (request.requests_per_minute is None) != (request.baseline_requests_per_minute is None):
            raise HTTPException(
                status_code=422,
                detail="Request volume and its baseline must be provided together.",
            )
        if (request.bytes_out_mb is None) != (request.baseline_bytes_out_mb is None):
            raise HTTPException(
                status_code=422,
                detail="Outbound data volume and its baseline must be provided together.",
            )
    elif not request.content.strip() and not (request.url or "").strip() and source != "auth":
        raise HTTPException(status_code=422, detail="Provide message content or a URL to analyze.")


def _check_ingest_authorization(authorization: str | None) -> None:
    expected_token = os.getenv("CYBERGUARD_INGEST_TOKEN", "")
    if len(expected_token) < 32:
        raise HTTPException(
            status_code=503,
            detail="Authenticated ingestion is not configured. Set CYBERGUARD_INGEST_TOKEN to a random secret of at least 32 characters.",
        )
    scheme, separator, supplied_token = (authorization or "").partition(" ")
    if (
        not separator
        or scheme.casefold() != "bearer"
        or not hmac.compare_digest(
            supplied_token.encode("utf-8"),
            expected_token.encode("utf-8"),
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/api/ingest", status_code=202)
def ingest_telemetry(
    request: TelemetryIngestRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    _check_ingest_authorization(authorization)
    _validate_analysis_input(request)

    event = analyze_event(request.model_dump())
    stable_key = f"{request.source_name.casefold()}:{request.source_event_id}"
    event["id"] = f"ING-{hashlib.sha256(stable_key.encode('utf-8')).hexdigest().upper()}"
    event["timestamp"] = request.observed_at.isoformat()
    event["source"] = request.source_name
    return storage.insert_event(event)


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    _validate_analysis_input(request)
    event = analyze_event(request.model_dump())
    return storage.insert_event(event)
