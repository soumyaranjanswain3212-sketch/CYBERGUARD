from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import storage
from .analyzer import analyze_event

app = FastAPI(
    title="CyberGuard Threat Analysis API",
    description="Analyze and persist security events for an authorized local deployment.",
    version="1.1.0",
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


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest) -> dict:
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
    event = analyze_event(request.model_dump())
    return storage.insert_event(event)
