from __future__ import annotations

import json
import os
import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from identity_attack_graph import __version__
from identity_attack_graph.api import create_app
from identity_attack_graph.cli import main
from identity_attack_graph.resources import resource_text


def smoke() -> int:
    with tempfile.TemporaryDirectory() as directory:
        os.chdir(directory)
        output = Path(directory) / "benchmark"
        with redirect_stdout(StringIO()):
            status = main(["benchmark", "--iterations", "2", "--out", str(output)])
        if status != 0:
            raise AssertionError("packaged default benchmark failed its quality gate")
        report = json.loads((output / "benchmark.json").read_text(encoding="utf-8"))
        if report["actual_paths"] != 7 or report["actual_edges"] != 14:
            raise AssertionError("packaged benchmark returned unexpected counts")
        app = create_app()
        if app.state.environment.name != "banking-platform-identity-lab":
            raise AssertionError("packaged API did not load its default environment")
        if "Identity Attack Graph" not in resource_text("web/index.html"):
            raise AssertionError("packaged dashboard resource is unavailable")
    print(json.dumps({"installed_version": __version__, "paths": 7, "edges": 14}))
    return 0


if __name__ == "__main__":
    raise SystemExit(smoke())
