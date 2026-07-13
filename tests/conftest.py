from __future__ import annotations

from pathlib import Path

import pytest

from identity_attack_graph.loader import load_environment
from identity_attack_graph.models import Environment


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def environment_path(repository_root: Path) -> Path:
    return repository_root / "fixtures/normalized/lab.json"


@pytest.fixture
def environment(environment_path: Path) -> Environment:
    return load_environment(environment_path)
