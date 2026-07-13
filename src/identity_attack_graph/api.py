from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import Response

from .analyzer import Analyzer
from .loader import load_environment, validate_references
from .models import Environment, Report, WhatIfReport, WhatIfRequest


def create_app(environment_path: Path | None = None) -> FastAPI:
    path = environment_path or Path(
        os.getenv("IDENTITY_GRAPH_ENVIRONMENT", "fixtures/normalized/lab.json")
    )
    environment = load_environment(path)
    app = FastAPI(
        title="Identity Attack Graph",
        version="0.1.0",
        description="Evidence-backed AWS IAM and Kubernetes RBAC attack paths.",
    )
    app.state.environment = environment

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
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
    def what_if(request: WhatIfRequest) -> WhatIfReport:
        try:
            return Analyzer(environment).what_if(request)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.post("/v1/analyze", response_model=Report)
    def analyze(submitted: Environment) -> Report:
        try:
            validate_references(submitted)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return Analyzer(submitted).analyze()

    web_root = Path(__file__).resolve().parents[2] / "web"
    if web_root.is_dir():
        app.mount("/assets", StaticFiles(directory=web_root), name="assets")

        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(web_root / "index.html")

    return app
