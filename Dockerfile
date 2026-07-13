FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN python -m pip install uv==0.11.23
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY fixtures ./fixtures
COPY web ./web
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN groupadd --gid 10001 identitygraph \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin identitygraph
COPY --from=build --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 README.md LICENSE ./
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["identity-graph"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
