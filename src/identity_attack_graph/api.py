from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import Request
from starlette.responses import Response

from . import __version__
from .analyzer import Analyzer
from .loader import MAX_INPUT_BYTES, load_environment, strict_json_object, validate_references
from .models import Environment, Report, WhatIfReport, WhatIfRequest
from .resources import packaged_path, resource_text


async def _strict_json_body(request: Request) -> None:
    body = await request.body()
    if len(body) > MAX_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="request body too large")
    try:
        strict_json_object(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {error}") from error


StrictJsonBody = Annotated[None, Depends(_strict_json_body)]


def create_app(environment_path: Path | None = None) -> FastAPI:
    configured = os.getenv("IDENTITY_GRAPH_ENVIRONMENT")
    if environment_path is not None or configured:
        environment = load_environment(environment_path or Path(configured or ""))
    else:
        with packaged_path("data/lab.json") as path:
            environment = load_environment(path)
    app = FastAPI(
        title="Identity Attack Graph",
        version=__version__,
        description="Evidence-backed AWS IAM and Kubernetes RBAC attack paths.",
    )
    app.state.environment = environment

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response: Response
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                response = JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
            else:
                if declared_length < 0:
                    response = JSONResponse({"detail": "invalid Content-Length"}, status_code=400)
                elif declared_length > MAX_INPUT_BYTES:
                    response = JSONResponse({"detail": "request body too large"}, status_code=413)
                else:
                    response = await call_next(request)
        else:
            response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "environment": environment.name}

    @app.get("/v1/report", response_model=Report)
    def report() -> Report:
        return Analyzer(environment).analyze()

    @app.get("/v1/graph")
    def graph() -> dict[str, object]:
        result = Analyzer(environment).analyze()
        return {"nodes": result.nodes, "edges": result.edges, "risk": result.risk}

    @app.get("/v1/paths")
    def paths() -> dict[str, object]:
        result = Analyzer(environment).analyze()
        return {"paths": result.paths, "risk": result.risk}

    @app.get("/v1/findings")
    def findings() -> dict[str, object]:
        result = Analyzer(environment).analyze()
        return {"findings": result.findings, "unsupported": result.unsupported_semantics}

    @app.post("/v1/what-if", response_model=WhatIfReport)
    def what_if(request: WhatIfRequest, _strict_json: StrictJsonBody) -> WhatIfReport:
        try:
            return Analyzer(environment).what_if(request)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.post("/v1/analyze", response_model=Report)
    def analyze(submitted: Environment, _strict_json: StrictJsonBody) -> Report:
        try:
            validate_references(submitted)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return Analyzer(submitted).analyze()

    @app.get("/assets/{asset_name}", include_in_schema=False)
    def asset(asset_name: str) -> Response:
        media_types = {"app.js": "text/javascript", "style.css": "text/css"}
        media_type = media_types.get(asset_name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return Response(resource_text(f"web/{asset_name}"), media_type=media_type)

    @app.get("/", include_in_schema=False)
    def dashboard() -> HTMLResponse:
        return HTMLResponse(resource_text("web/index.html"))

    return app
