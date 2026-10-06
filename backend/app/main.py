from __future__ import annotations

import hashlib
import hmac
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import storage
from .analyzer import analyze_cloudflare_firewall_event, analyze_event
from .cloudflare import CloudflareBatchError, decode_logpush_batch
from .security import (
    AuthenticationConfigurationError,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    AnalystSession,
    authenticate,
    authentication_ready,
    create_session,
    read_session,
    session_cookie_secure,
)
from .url_model import get_url_model_status


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.initialize()
    yield

app = FastAPI(
    title="CyberGuard Threat Analysis API",
    description="Analyze and persist security events for an authenticated deployment.",
    version="1.3.0",
    lifespan=lifespan,
)

origins = os.getenv(
    "CYBERGUARD_CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
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


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=1024)


_failed_login_attempts: dict[str, list[float]] = {}
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_ATTEMPT_LIMIT = 5


@app.get("/health")
def health() -> dict:
    url_model = get_url_model_status()
    return {
        "status": "ok",
        "storage": "sqlite",
        "engine": "hybrid-url-model-and-rules" if url_model["available"] else "transparent-rule-based",
        "url_model": url_model,
        "authentication_configured": authentication_ready(),
    }


def _analyst_session(request: Request) -> AnalystSession:
    try:
        session = read_session(request.cookies.get(SESSION_COOKIE_NAME))
    except AuthenticationConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    if session is None:
        raise HTTPException(status_code=401, detail="Sign in to access the analyst dashboard.")
    return session


def _require_csrf(request: Request, csrf_token: str | None) -> AnalystSession:
    session = _analyst_session(request)
    if not csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(status_code=403, detail="A valid CSRF token is required.")
    return session


def _login_key() -> str:
    return "analyst-account"


def _check_login_rate_limit() -> None:
    now = time.monotonic()
    attempts = [
        timestamp
        for timestamp in _failed_login_attempts.get(_login_key(), [])
        if now - timestamp < _LOGIN_WINDOW_SECONDS
    ]
    _failed_login_attempts[_login_key()] = attempts
    if len(attempts) >= _LOGIN_ATTEMPT_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Too many failed sign-in attempts. Wait five minutes and try again.",
            headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
        )


def _record_failed_login() -> None:
    _failed_login_attempts.setdefault(_login_key(), []).append(time.monotonic())


@app.post("/api/auth/login")
def login(request: LoginRequest, response: Response) -> dict:
    try:
        _check_login_rate_limit()
        if not authenticate(request.username, request.password):
            _record_failed_login()
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        cookie_value, session = create_session(request.username.strip())
        secure = session_cookie_secure()
    except AuthenticationConfigurationError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error

    _failed_login_attempts.pop(_login_key(), None)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_value,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    return {"username": session.username, "csrf_token": session.csrf_token}


@app.get("/api/auth/session")
def get_auth_session(request: Request) -> dict:
    session = _analyst_session(request)
    return {"username": session.username, "csrf_token": session.csrf_token}


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict:
    _require_csrf(request, csrf_token)
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=session_cookie_secure(),
        samesite="strict",
        path="/",
    )
    return {"logged_out": True}


@app.get("/api/events")
def get_events(request: Request, limit: int = 500, offset: int = 0) -> list[dict]:
    _analyst_session(request)
    if not 1 <= limit <= 1000 or offset < 0:
        raise HTTPException(status_code=422, detail="Limit must be 1–1000 and offset cannot be negative.")
    return storage.list_events(limit=limit, offset=offset)


@app.get("/api/summary")
def get_summary(request: Request) -> dict:
    _analyst_session(request)
    return storage.get_summary()


@app.patch("/api/events/{event_id}")
def update_event(
    request: Request,
    event_id: str,
    update: StatusUpdate,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict:
    _require_csrf(request, csrf_token)
    event = storage.update_status(event_id, update.status)
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


@app.post("/api/ingest/cloudflare/logpush")
async def ingest_cloudflare_logpush(request: Request) -> dict:
    _check_ingest_authorization(request.headers.get("authorization"))
    body_chunks: list[bytes] = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Compressed Logpush batch exceeds the 10 MiB request limit.")
        body_chunks.append(chunk)
    try:
        records, is_validation_probe = decode_logpush_batch(
            b"".join(body_chunks),
            request.headers.get("content-encoding", ""),
        )
        if is_validation_probe:
            return {"records_processed": 0, "validation_probe": True}
        analyzed = [analyze_cloudflare_firewall_event(record) for record in records]
    except (CloudflareBatchError, ValueError, OverflowError, OSError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    saved = storage.insert_events(analyzed)
    return {"records_processed": len(saved), "validation_probe": False}


@app.post("/api/analyze")
def analyze(
    request: Request,
    analysis: AnalyzeRequest,
    csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> dict:
    _require_csrf(request, csrf_token)
    _validate_analysis_input(analysis)
    event = analyze_event(analysis.model_dump())
    return storage.insert_event(event)
