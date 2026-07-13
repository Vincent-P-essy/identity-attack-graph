from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from .adapters import import_aws_authorization_details, import_kubernetes_file
from .analyzer import Analyzer
from .api import create_app
from .benchmark import benchmark
from .loader import load_environment
from .models import (
    Environment,
    Identity,
    IdentityGroup,
    KubernetesBinding,
    KubernetesRole,
    PermissionMutation,
    Resource,
    WhatIfRequest,
)
from .reporting import write_report, write_what_if


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="identity-graph")
    root.add_argument("--environment", type=Path, default=Path("fixtures/normalized/lab.json"))
    commands = root.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="build paths and write an evidence report")
    analyze.add_argument("--out", type=Path, default=Path("reports"))

    what_if = commands.add_parser("what-if", help="remove permissions and recalculate paths")
    what_if.add_argument(
        "--remove",
        action="append",
        required=True,
        metavar="STATEMENT_ID=ACTION",
        help="permission or RBAC verb to remove; repeatable",
    )
    what_if.add_argument("--out", type=Path, default=Path("reports/what-if.json"))

    run_benchmark = commands.add_parser("benchmark", help="measure the versioned lab")
    run_benchmark.add_argument("--truth", type=Path, default=Path("fixtures/ground-truth.json"))
    run_benchmark.add_argument("--out", type=Path, default=Path("reports"))
    run_benchmark.add_argument("--iterations", type=int, default=50)

    normalize = commands.add_parser("normalize", help="import AWS and Kubernetes exports")
    normalize.add_argument("--aws", type=Path)
    normalize.add_argument("--kubernetes", type=Path)
    normalize.add_argument("--account-id", default="000000000000")
    normalize.add_argument("--name", default="imported-environment")
    normalize.add_argument("--out", type=Path, required=True)

    serve = commands.add_parser("serve", help="start the local API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return root


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "normalize":
        return _normalize(arguments)
    environment = load_environment(arguments.environment)
    if arguments.command == "analyze":
        analysis_report = Analyzer(environment).analyze()
        write_report(analysis_report, arguments.out)
        print(analysis_report.model_dump_json(indent=2))
        return 0
    if arguments.command == "what-if":
        mutations = [_parse_mutation(value) for value in arguments.remove]
        simulation = Analyzer(environment).what_if(WhatIfRequest(mutations=mutations))
        write_what_if(simulation, arguments.out)
        print(simulation.model_dump_json(indent=2))
        return 0
    if arguments.command == "benchmark":
        benchmark_report = benchmark(
            arguments.environment,
            arguments.truth,
            arguments.out,
            iterations=arguments.iterations,
        )
        print(json.dumps(benchmark_report, indent=2, sort_keys=True))
        return int(
            benchmark_report["path_recall"] != 1
            or benchmark_report["path_precision"] != 1
            or not benchmark_report["deterministic"]
        )
    if arguments.command == "serve":
        uvicorn.run(create_app(arguments.environment), host=arguments.host, port=arguments.port)
        return 0
    raise AssertionError("unreachable command")


def _parse_mutation(value: str) -> PermissionMutation:
    statement, separator, action = value.partition("=")
    if not separator or not statement or not action:
        raise ValueError("--remove must use STATEMENT_ID=ACTION")
    return PermissionMutation(statement_id=statement, action=action)


def _normalize(arguments: argparse.Namespace) -> int:
    identities: list[Identity] = []
    groups: list[IdentityGroup] = []
    roles: list[KubernetesRole] = []
    bindings: list[KubernetesBinding] = []
    resources: list[Resource] = []
    if arguments.aws:
        payload = json.loads(arguments.aws.read_text(encoding="utf-8"))
        aws_identities, aws_groups = import_aws_authorization_details(
            payload, account_id=arguments.account_id
        )
        identities.extend(aws_identities)
        groups.extend(aws_groups)
    if arguments.kubernetes:
        k8s_identities, roles, bindings, resources = import_kubernetes_file(arguments.kubernetes)
        identities.extend(k8s_identities)
    environment = Environment(
        name=arguments.name,
        identities=identities,
        groups=groups,
        resources=resources,
        kubernetes_roles=roles,
        kubernetes_bindings=bindings,
    )
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(environment.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(arguments.out), "identities": len(identities)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
