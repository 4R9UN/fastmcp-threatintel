"""Visualization and reporting utilities for threat intelligence data."""

import json
from datetime import datetime
from typing import Any

from .threatintel import IOC, APTAttribution


def create_ioc_table(iocs: list[IOC]) -> str:
    """Create a markdown table from IOC results."""
    if not iocs:
        return "No IOCs to display."

    # Create markdown table
    table_lines = [
        "| IOC | Type | Reputation | Score | Reports |",
        "|-----|------|------------|-------|---------|",
    ]

    for ioc in iocs:
        reputation = ioc.reputation or "Unknown"
        score = f"{ioc.score:.1f}" if ioc.score is not None else "N/A"
        reports_summary = "; ".join(ioc.reports[:2]) if ioc.reports else "No reports"

        # Truncate long values
        value = ioc.value[:50] + "..." if len(ioc.value) > 50 else ioc.value
        reports_summary = (
            reports_summary[:100] + "..." if len(reports_summary) > 100 else reports_summary
        )

        table_lines.append(
            f"| {value} | {ioc.type.upper()} | {reputation} | {score} | {reports_summary} |"
        )

    return "\n".join(table_lines)


def create_network_graph(
    iocs: list[IOC], attribution: APTAttribution | None = None
) -> dict[str, Any]:
    """Create a D3.js compatible network graph of IOCs and their relationships."""
    nodes = []
    links = []

    # Add IOC nodes
    for i, ioc in enumerate(iocs):
        color = (
            "#ff4444"
            if ioc.reputation == "Malicious"
            else "#ffaa44"
            if ioc.reputation == "Suspicious"
            else "#44aa44"
        )
        nodes.append(
            {
                "id": f"ioc_{i}",
                "label": ioc.value,
                "type": ioc.type,
                "reputation": ioc.reputation,
                "score": ioc.score,
                "group": 1,
                "color": color,
                "size": max(10, (ioc.score or 0) / 5) if ioc.score else 10,
            }
        )

    # Add attribution node if available
    if attribution and attribution.actor and attribution.actor != "Unknown":
        nodes.append(
            {
                "id": "apt_actor",
                "label": attribution.actor,
                "type": "apt",
                "group": 2,
                "color": "#aa44aa",
                "size": 20,
            }
        )

        # Link IOCs to APT actor
        for i in range(len(iocs)):
            links.append(
                {
                    "source": f"ioc_{i}",
                    "target": "apt_actor",
                    "type": "attributed_to",
                    "strength": attribution.confidence / 100 if attribution.confidence else 0.5,
                }
            )

    # Add geolocation nodes for IP addresses
    countries = {}
    for i, ioc in enumerate(iocs):
        if ioc.type == "ip" and ioc.country:
            country_id = f"country_{ioc.country}"
            if country_id not in countries:
                countries[country_id] = {
                    "id": country_id,
                    "label": ioc.country,
                    "type": "country",
                    "group": 3,
                    "color": "#4444aa",
                    "size": 15,
                }
                nodes.append(countries[country_id])

            links.append(
                {"source": f"ioc_{i}", "target": country_id, "type": "located_in", "strength": 0.3}
            )

    return {
        "nodes": nodes,
        "links": links,
        "metadata": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "generated_at": datetime.now().isoformat(),
        },
    }


def create_interactive_report(
    iocs: list[IOC],
    attribution: APTAttribution | None = None,
    report_id: str = "report",
    include_graph: bool = True,
) -> str:
    """Create an interactive HTML report with visualizations."""

    # Calculate summary statistics
    total_iocs = len(iocs)
    malicious_count = sum(1 for ioc in iocs if ioc.reputation == "Malicious")
    suspicious_count = sum(1 for ioc in iocs if ioc.reputation == "Suspicious")
    clean_count = sum(1 for ioc in iocs if ioc.reputation == "Clean")

    # Generate network graph data
    graph_data = create_network_graph(iocs, attribution) if include_graph else None

    # Create HTML report
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatIntel Report - {report_id}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .malicious {{ color: #dc3545; }}
        .suspicious {{ color: #ffc107; }}
        .clean {{ color: #28a745; }}
        .total {{ color: #6c757d; }}

        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}

        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .ioc-table th,
        .ioc-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .ioc-table th {{
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }}
        .ioc-table tr:hover {{
            background-color: #f5f5f5;
        }}

        .reputation-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .reputation-malicious {{
            background-color: #dc3545;
            color: white;
        }}
        .reputation-suspicious {{
            background-color: #ffc107;
            color: #212529;
        }}
        .reputation-clean {{
            background-color: #28a745;
            color: white;
        }}
        .reputation-unknown {{
            background-color: #6c757d;
            color: white;
        }}

        #network-graph {{
            width: 100%;
            height: 500px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fafafa;
        }}

        .attribution-card {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
        }}
        .attribution-card h3 {{
            margin-top: 0;
            font-size: 1.5em;
        }}
        .confidence-bar {{
            background: rgba(255,255,255,0.3);
            border-radius: 10px;
            height: 20px;
            margin: 10px 0;
            overflow: hidden;
        }}
        .confidence-fill {{
            background: rgba(255,255,255,0.8);
            height: 100%;
            border-radius: 10px;
            transition: width 0.5s ease;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ThreatIntel Analysis Report</h1>
            <p>Report ID: {report_id} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-number total">{total_iocs}</div>
                <div>Total IOCs</div>
            </div>
            <div class="stat-card">
                <div class="stat-number malicious">{malicious_count}</div>
                <div>Malicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-number suspicious">{suspicious_count}</div>
                <div>Suspicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-number clean">{clean_count}</div>
                <div>Clean</div>
            </div>
        </div>

        <div class="content">
"""

    # Add attribution section if available
    if attribution and attribution.actor and attribution.actor != "Unknown":
        html_content += f"""
            <div class="section">
                <h2>🎯 APT Attribution</h2>
                <div class="attribution-card">
                    <h3>{attribution.actor}</h3>
                    <p><strong>Group:</strong> {attribution.group}</p>
                    <p><strong>Target Region:</strong> {attribution.target_region}</p>
                    <p><strong>Motive:</strong> {attribution.motive}</p>
                    <p><strong>Confidence:</strong></p>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {attribution.confidence}%"></div>
                    </div>
                    <p>{attribution.confidence}% confidence</p>
                    <p><strong>Summary:</strong> {attribution.summary}</p>
                    <p><strong>MITRE ATT&CK Techniques:</strong> {", ".join(attribution.mitre_techniques)}</p>
                </div>
            </div>
"""

    # Add IOC table
    html_content += """
            <div class="section">
                <h2>📊 IOC Analysis Results</h2>
                <table class="ioc-table">
                    <thead>
                        <tr>
                            <th>IOC</th>
                            <th>Type</th>
                            <th>Reputation</th>
                            <th>Score</th>
                            <th>Location</th>
                            <th>Reports</th>
                        </tr>
                    </thead>
                    <tbody>
"""

    # Add IOC rows
    for ioc in iocs:
        reputation_class = (
            f"reputation-{ioc.reputation.lower()}" if ioc.reputation else "reputation-unknown"
        )
        reputation_text = ioc.reputation or "Unknown"
        score_text = f"{ioc.score:.1f}" if ioc.score is not None else "N/A"
        location = (
            f"{ioc.city}, {ioc.country}" if ioc.city and ioc.country else (ioc.country or "Unknown")
        )
        reports_summary = "; ".join(ioc.reports[:2]) if ioc.reports else "No reports"

        html_content += f"""
                        <tr>
                            <td><code>{ioc.value}</code></td>
                            <td><strong>{ioc.type.upper()}</strong></td>
                            <td><span class="reputation-badge {reputation_class}">{reputation_text}</span></td>
                            <td>{score_text}</td>
                            <td>{location}</td>
                            <td title="{reports_summary}">{reports_summary[:100]}{"..." if len(reports_summary) > 100 else ""}</td>
                        </tr>
"""

    html_content += """
                    </tbody>
                </table>
            </div>
"""

    # Add network graph if enabled
    if include_graph and graph_data:
        html_content += f"""
            <div class="section">
                <h2>🔗 Network Visualization</h2>
                <div id="network-graph"></div>
            </div>

            <script>
                // Network graph visualization
                const graphData = {json.dumps(graph_data)};

                const width = document.getElementById('network-graph').clientWidth;
                const height = 500;

                const svg = d3.select("#network-graph")
                    .append("svg")
                    .attr("width", width)
                    .attr("height", height);

                const simulation = d3.forceSimulation(graphData.nodes)
                    .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
                    .force("charge", d3.forceManyBody().strength(-300))
                    .force("center", d3.forceCenter(width / 2, height / 2));

                const link = svg.append("g")
                    .selectAll("line")
                    .data(graphData.links)
                    .enter().append("line")
                    .attr("stroke", "#999")
                    .attr("stroke-opacity", 0.6)
                    .attr("stroke-width", 2);

                const node = svg.append("g")
                    .selectAll("circle")
                    .data(graphData.nodes)
                    .enter().append("circle")
                    .attr("r", d => d.size)
                    .attr("fill", d => d.color)
                    .attr("stroke", "#fff")
                    .attr("stroke-width", 2)
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended));

                const label = svg.append("g")
                    .selectAll("text")
                    .data(graphData.nodes)
                    .enter().append("text")
                    .text(d => d.label.length > 20 ? d.label.substring(0, 20) + "..." : d.label)
                    .attr("font-size", "10px")
                    .attr("text-anchor", "middle")
                    .attr("dy", 3);

                node.append("title")
                    .text(d => `${{d.label}} (${{d.type}}) - ${{d.reputation || 'Unknown'}}`);

                simulation.on("tick", () => {{
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);

                    node
                        .attr("cx", d => d.x)
                        .attr("cy", d => d.y);

                    label
                        .attr("x", d => d.x)
                        .attr("y", d => d.y);
                }});

                function dragstarted(event, d) {{
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }}

                function dragged(event, d) {{
                    d.fx = event.x;
                    d.fy = event.y;
                }}

                function dragended(event, d) {{
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }}
            </script>
"""

    html_content += """
        </div>
    </div>
</body>
</html>
"""

    return html_content
