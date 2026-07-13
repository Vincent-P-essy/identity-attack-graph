from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .models import Report, WhatIfReport


def write_report(report: Report, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    graph_payload = {
        "nodes": [item.model_dump(mode="json") for item in report.nodes],
        "edges": [item.model_dump(mode="json") for item in report.edges],
    }
    (output / "graph.json").write_text(
        json.dumps(graph_payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    _write_paths(output / "paths.csv", report)
    (output / "REPORT.md").write_text(_markdown(report), encoding="utf-8")
    (output / "graph.dot").write_text(_dot(report), encoding="utf-8")


def write_what_if(report: WhatIfReport, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _write_paths(path: Path, report: Report) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "path_id",
                "entrypoint",
                "target",
                "risk",
                "effort",
                "exploitability",
                "confidence",
                "nodes",
                "techniques",
            ]
        )
        for item in report.paths:
            writer.writerow(
                [
                    _csv_safe(item.id),
                    _csv_safe(item.entrypoint),
                    _csv_safe(item.target),
                    item.risk,
                    item.effort,
                    item.exploitability,
                    item.confidence,
                    _csv_safe(" -> ".join(item.node_ids)),
                    _csv_safe(";".join(item.techniques)),
                ]
            )


def _markdown(report: Report) -> str:
    lines = [
        f"# Identity attack graph: {_markdown_safe(report.environment)}",
        "",
        f"- Reachable paths: **{report.risk.path_count}**",
        f"- Reachable configured targets: **{report.risk.crown_jewels_reachable}**",
        f"- Maximum path risk: **{report.risk.maximum_path_risk:.3f}/100**",
        f"- Aggregate prioritization score: **{report.risk.aggregate_risk:.3f}/100**",
        f"- Analysis latency: **{report.elapsed_ms:.3f} ms**",
        "",
        "| Entrypoint | Target | Risk | Effort | Path | ATT&CK |",
        "|---|---|---:|---:|---|---|",
    ]
    for path in report.paths:
        lines.append(
            f"| {_markdown_safe(path.entrypoint)} | {_markdown_safe(path.target)} | "
            f"{path.risk:.3f} | {path.effort:.3f} | "
            f"{_markdown_safe(' → '.join(path.node_ids))} | "
            f"{_markdown_safe(', '.join(path.techniques))} |"
        )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Severity | Category | Subject | Title |",
            "|---|---|---|---|",
        ]
    )
    for finding in report.findings:
        lines.append(
            f"| {finding.severity.value} | {_markdown_safe(finding.category)} | "
            f"{_markdown_safe(finding.subject)} | {_markdown_safe(finding.title)} |"
        )
    if report.unsupported_semantics:
        lines.extend(["", "## Fail-closed semantics", ""])
        lines.extend(f"- {_markdown_safe(item)}" for item in report.unsupported_semantics)
    lines.extend(
        [
            "",
            "Risk is a deterministic prioritization heuristic, not breach probability. "
            "Review every edge's evidence before remediation.",
            "",
        ]
    )
    return "\n".join(lines)


def _dot(report: Report) -> str:
    lines = ["digraph identity_attack_graph {", '  rankdir="LR";']
    for node in report.nodes:
        shape = "doubleoctagon" if node.crown_jewel else "box"
        lines.append(f"  {_dot_quote(node.id)} [label={_dot_quote(node.label)}, shape={shape}];")
    for edge in report.edges:
        lines.append(
            f"  {_dot_quote(edge.source)} -> {_dot_quote(edge.target)} "
            f"[label={_dot_quote(edge.label)}];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _dot_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _markdown_safe(value: str) -> str:
    return html.escape(value, quote=True).replace("|", "&#124;")


def _csv_safe(value: str) -> str:
    stripped = value.lstrip()
    return f"'{value}" if stripped.startswith(("=", "+", "-", "@")) else value
