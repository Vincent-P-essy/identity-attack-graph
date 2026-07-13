from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import as_file, files
from pathlib import Path

_DEVELOPMENT_FALLBACKS = {
    "data/lab.json": "fixtures/normalized/lab.json",
    "data/ground-truth.json": "fixtures/ground-truth.json",
    "data/uv.lock": "uv.lock",
    "web/index.html": "web/index.html",
    "web/app.js": "web/app.js",
    "web/style.css": "web/style.css",
}


def resource_text(relative: str) -> str:
    resource = files("identity_attack_graph").joinpath(relative)
    if resource.is_file():
        return resource.read_text(encoding="utf-8")
    return _development_path(relative).read_text(encoding="utf-8")


def package_source_sha256() -> str:
    root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@contextmanager
def packaged_path(relative: str) -> Iterator[Path]:
    resource = files("identity_attack_graph").joinpath(relative)
    if resource.is_file():
        with as_file(resource) as path:
            yield path
        return
    yield _development_path(relative)


def _development_path(relative: str) -> Path:
    fallback = _DEVELOPMENT_FALLBACKS.get(relative)
    if fallback is None:
        raise FileNotFoundError(f"unknown package resource {relative!r}")
    path = Path(__file__).resolve().parents[2] / fallback
    if not path.is_file():
        raise FileNotFoundError(f"package resource is unavailable: {relative}")
    return path
