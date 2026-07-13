const svg = document.querySelector("#graph");
const namespace = "http://www.w3.org/2000/svg";

async function load() {
  const response = await fetch("/v1/report");
  const report = await response.json();
  document.querySelector("#path-count").textContent = report.risk.path_count;
  document.querySelector("#risk").textContent = `${report.risk.aggregate_risk.toFixed(1)}/100`;
  document.querySelector("#targets").textContent = report.risk.crown_jewels_reachable;
  document.querySelector("#latency").textContent = `${report.elapsed_ms.toFixed(2)} ms`;
  renderGraph(report.nodes, report.edges);
  renderPaths(report.paths);
}

function renderGraph(nodes, edges) {
  svg.replaceChildren();
  const columns = {aws: 170, kubernetes: 620};
  const positions = new Map();
  const byProvider = {aws: [], kubernetes: []};
  nodes.forEach(node => byProvider[node.provider].push(node));
  Object.entries(byProvider).forEach(([provider, items]) => {
    items.forEach((node, index) => positions.set(node.id, {
      x: columns[provider] + (node.kind === "target" ? 150 : node.kind === "workload" ? 75 : 0),
      y: 45 + index * (430 / Math.max(1, items.length - 1))
    }));
  });
  edges.forEach(edge => {
    const start = positions.get(edge.source), end = positions.get(edge.target);
    if (!start || !end) return;
    const line = document.createElementNS(namespace, "line");
    Object.entries({x1:start.x, y1:start.y, x2:end.x, y2:end.y}).forEach(([k,v]) => line.setAttribute(k,v));
    line.setAttribute("class", "edge");
    const title = document.createElementNS(namespace, "title"); title.textContent = edge.label; line.append(title); svg.append(line);
  });
  nodes.forEach(node => {
    const point = positions.get(node.id);
    const group = document.createElementNS(namespace, "g"); group.setAttribute("class", `node ${node.kind}`);
    const circle = document.createElementNS(namespace, "circle"); circle.setAttribute("cx", point.x); circle.setAttribute("cy", point.y); circle.setAttribute("r", node.crown_jewel ? 10 : 7);
    const text = document.createElementNS(namespace, "text"); text.setAttribute("x", point.x + 14); text.setAttribute("y", point.y + 4); text.textContent = node.label;
    group.append(circle, text); svg.append(group);
  });
}

function renderPaths(paths) {
  const body = document.querySelector("#paths"); body.replaceChildren();
  paths.slice(0, 10).forEach(path => {
    const row = document.createElement("tr");
    [path.entrypoint, path.target, path.risk.toFixed(2), path.node_ids.join(" → ")].forEach(value => {
      const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
    }); body.append(row);
  });
}

document.querySelector("#simulate").addEventListener("click", async () => {
  const [statement_id, action] = document.querySelector("#statement").value.split("=");
  const response = await fetch("/v1/what-if", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({mutations:[{statement_id, action}]})});
  const result = await response.json();
  document.querySelector("#what-if").textContent = response.ok
    ? `${result.eliminated_paths.length} paths removed · −${result.risk_reduction.toFixed(2)} risk · ${result.broken_business_operations.length} business operations affected`
    : result.detail;
});

load().catch(error => { document.querySelector("#legend").textContent = String(error); });
