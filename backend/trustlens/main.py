"""TrustLens FastAPI application."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import api_router
from .config import Settings, get_settings
from .db import engine, init_db
from .security.redaction import safe_error
from .worker.runner import worker_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("trustlens")


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.auto_create_schema:
        init_db()
        logger.info("database schema ready (%s)", engine.dialect.name)
    stop_event = asyncio.Event()
    worker_task: asyncio.Task | None = None
    if settings.worker_enabled:
        worker_task = asyncio.create_task(worker_loop(stop_event, settings))
    yield
    if worker_task is not None:
        stop_event.set()
        try:
            await asyncio.wait_for(worker_task, timeout=10)
        except asyncio.TimeoutError:
            worker_task.cancel()
    engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="TrustLens API",
        description=(
            "Evidence-first web threat detection and digital trust intelligence. "
            "Passive checks only; no exploitation, no active scanning."
        ),
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:  # unhandled exceptions are converted by the handler below
            raise
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if request.url.path.startswith("/api/"):
            logger.info(
                "request %s %s %s %s %.0fms",
                request_id,
                request.method,
                request.url.path,
                response.status_code,
                (time.monotonic() - started) * 1000,
            )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "message": exc.detail if isinstance(exc.detail, str) else "Request failed.",
                    "status": exc.status_code,
                    "request_id": _request_id(request),
                }
            },
            headers=getattr(exc, "headers", None) or {},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        fields = []
        for item in exc.errors()[:6]:
            location = ".".join(str(part) for part in item.get("loc", []) if part != "body")
            fields.append(f"{location}: {item.get('msg', 'invalid')}")
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "message": "Invalid request: " + "; ".join(fields),
                    "status": 422,
                    "request_id": _request_id(request),
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        logger.exception("unhandled error %s", _request_id(request))
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": "An internal error occurred. No sensitive details are exposed.",
                    "status": 500,
                    "request_id": _request_id(request),
                }
            },
        )

    @app.get("/", include_in_schema=False)
    def root():
        return {
            "name": "TrustLens API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health",
            "api": settings.api_prefix,
        }

    @app.get("/health", tags=["health"])
    def health():
        return {"status": "ok", "service": "trustlens-api", "version": "1.0.0"}

    @app.get("/ready", tags=["health"])
    def ready():
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:
            logger.warning("readiness failed: %s", safe_error(exc, 120))
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "database": "unavailable"},
            )
        return {"status": "ready", "database": "ok"}

    app.include_router(api_router, prefix=settings.api_prefix)
    return app


app = create_app()
