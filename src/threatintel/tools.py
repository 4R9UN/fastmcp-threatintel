"""Registers the tools with the MCP server."""

import asyncio
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from tqdm.asyncio import tqdm
except ImportError:
    # Fallback for when tqdm.asyncio is not available

    class MockTqdm:
        @staticmethod
        def as_completed(tasks, desc="Processing"):
            return asyncio.as_completed(tasks)

    tqdm = MockTqdm()

from fastmcp import Context, FastMCP

from .threatintel import (
    IOC,
    APTAttribution,
    check_api_keys,
    query_abuseipdb,
    query_ipinfo,
    query_otx,
    query_virustotal,
)
from .visualizations import (
    create_interactive_report,
    create_ioc_table,
    create_network_graph,
)

# Configure logger
logger = logging.getLogger("threatintel.tools")


async def get_ioc_type(ioc_string: str, ctx: Context) -> str:
    """Determines the IOC type from the string pattern."""
    # IP address pattern
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc_string):
        return "ip"

    # File hash patterns
    if re.match(r"^[a-fA-F0-9]{32}$", ioc_string):
        return "md5"
    elif re.match(r"^[a-fA-F0-9]{40}$", ioc_string):
        return "sha1"
    elif re.match(r"^[a-fA-F0-9]{64}$", ioc_string):
        return "sha256"

    # URL pattern with protocol and path (more specific)
    if re.match(r"^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w\.-]*)*\/?$", ioc_string):
        return "url"

    # Domain pattern (less specific, checked after URL)
    if re.match(
        r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$",
        ioc_string,
    ):
        return "domain"

    # Default fallback for unknown patterns
    await ctx.warning(f"Could not determine IOC type for: {ioc_string}")
    return "unknown"


async def process_single_ioc(ioc_value: str, ioc_type: str, ctx: Context) -> IOC:
    """Process a single IOC by querying all available intelligence sources in parallel."""
    await ctx.info(f"Processing {ioc_type}: {ioc_value}")

    # Create tasks for each intelligence source
    tasks = []

    # Always query VirusTotal and OTX
    tasks.append(query_virustotal(ioc_value, ioc_type, ctx=ctx))
    tasks.append(query_otx(ioc_value, ioc_type, ctx=ctx))

    # Only query AbuseIPDB for IP addresses
    if ioc_type.lower() == "ip":
        tasks.append(query_abuseipdb(ioc_value, ioc_type, ctx=ctx))

    # Execute all queries in parallel
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        await ctx.error(f"Error querying intelligence sources: {str(e)}")
        return IOC(
            value=ioc_value,
            type=ioc_type,
            reputation="Unknown",
            reports=[f"Error: {str(e)}"],
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Process results and handle any exceptions
    ioc_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            source = ["VirusTotal", "OTX", "AbuseIPDB"][min(i, 2)]
            await ctx.error(f"Error from {source}: {str(result)}")
            # Create an empty result for this source
            ioc_results.append(
                IOC(
                    value=ioc_value,
                    type=ioc_type,
                    reputation="Unknown",
                    reports=[f"{source} error: {str(result)}"],
                    score=None,
                    abuseipdb_confidence=None,
                    first_seen=None,
                    last_seen=None,
                    city=None,
                    region=None,
                    country=None,
                    asn=None,
                    location=None,
                )
            )
        else:
            ioc_results.append(result)

    # Extract all sources
    otx = next(
        (r for r in ioc_results if r.reports and "OTX" in r.reports[0]),
        IOC(
            value=ioc_value,
            type=ioc_type,
            reputation="Unknown",
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        ),
    )
    abuse = next(
        (r for r in ioc_results if r.reports and "AbuseIPDB" in r.reports[0]),
        IOC(
            value=ioc_value,
            type=ioc_type,
            reputation="Unknown",
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        ),
    )

    # Determine overall reputation
    reputations = [r.reputation for r in ioc_results if r.reputation is not None]
    if "Malicious" in reputations:
        reputation = "Malicious"
    elif "Suspicious" in reputations:
        reputation = "Suspicious"
    elif reputations and all(r == "Clean" for r in reputations):
        reputation = "Clean"
    else:
        reputation = "Unknown"

    # Calculate aggregate score if available
    scores = [r.score for r in ioc_results if r.score is not None]
    score = sum(scores) / len(scores) if scores else None

    # Combine all reports, engines, and tags
    all_reports = []
    for r in ioc_results:
        all_reports.extend(r.reports or [])

    all_engines = []
    for r in ioc_results:
        all_engines.extend(r.engines or [])

    all_tags = set()
    for r in ioc_results:
        all_tags.update(r.tags or [])

    # Get earliest first_seen and latest last_seen
    first_seen_dates = [r.first_seen for r in ioc_results if r.first_seen]
    last_seen_dates = [r.last_seen for r in ioc_results if r.last_seen]

    first_seen = min(first_seen_dates) if first_seen_dates else None
    last_seen = max(last_seen_dates) if last_seen_dates else None

    # Extract geolocation data (prioritize from sources that provide it)
    city = next((r.city for r in ioc_results if r.city), None)
    region = next((r.region for r in ioc_results if r.region), None)
    country = next((r.country for r in ioc_results if r.country), None)
    asn = next((r.asn for r in ioc_results if r.asn), None)
    location = next((r.location for r in ioc_results if r.location), None)

    # Create combined IOC result
    return IOC(
        value=ioc_value,
        type=ioc_type,
        reputation=reputation,
        score=round(score, 1) if score is not None else None,
        engines=all_engines,
        reports=all_reports,
        otx_pulses=otx.otx_pulses,
        abuseipdb_confidence=abuse.abuseipdb_confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        tags=list(all_tags),
        city=city,
        region=region,
        country=country,
        asn=asn,
        location=location,
    )


async def analyze_iocs_from_file(file_path: str, ctx: Context) -> str:
    """Read IOCs from a file and analyze them."""
    try:
        path = Path(file_path)
        if not path.exists():
            await ctx.error(f"File not found: {file_path}")
            return "Error: File not found."

        with open(path, encoding="utf-8") as f:
            iocs = [line.strip() for line in f if line.strip()]

        if not iocs:
            return "No IOCs found in the file."

        # Process IOCs by calling the analyze_iocs tool function directly
        return await _analyze_iocs_impl(iocs=[{"value": ioc} for ioc in iocs], ctx=ctx)

    except Exception as e:
        await ctx.error(f"Error processing file: {str(e)}")
        return f"Error: {str(e)}"


async def determine_attribution(iocs: list[IOC], ctx: Context) -> APTAttribution:
    """
    Determine APT attribution based on IOC characteristics.

    In a real implementation, this would use machine learning models,
    threat intelligence databases, and pattern recognition algorithms.
    This is a simplified demo version.
    """
    # Extract all tags and metadata for analysis
    all_tags = set()
    all_reports = []
    pulse_names = []

    for ioc in iocs:
        all_tags.update(ioc.tags or [])
        all_reports.extend(ioc.reports or [])
        if hasattr(ioc, "otx_pulses") and ioc.otx_pulses:
            pulse_names.extend(ioc.otx_pulses)

    # Define comprehensive attribution patterns (in a real system, this would be much more sophisticated)
    apt_patterns = {
        "APT29": {
            "tags": {
                "Russia",
                "CozyBear",
                "Cozy Bear",
                "SVR",
                "government",
                "APT29",
                "Nobelium",
                "The Dukes",
            },
            "techniques": ["T1566", "T1104", "T1573"],
            "group": "Cozy Bear",
            "region": "North America, Europe",
            "motive": "Espionage",
            "summary": "APT29, also known as Cozy Bear, is a Russian state-sponsored group active since at least 2008. Recent activity includes targeting government and critical infrastructure in 2024.",
        },
        "APT28": {
            "tags": {
                "Russia",
                "FancyBear",
                "Fancy Bear",
                "GRU",
                "military",
                "APT28",
                "Fighting Ursa",
                "Sofacy",
                "Sednit",
                "Pawn Storm",
                "Strontium",
            },
            "techniques": ["T1566.001", "T1012", "T1489"],
            "group": "Fancy Bear",
            "region": "Eastern Europe, NATO countries",
            "motive": "Military Intelligence",
            "summary": "APT28, also known as Fancy Bear or Fighting Ursa, is a Russian military intelligence group that primarily targets government, military, and security organizations.",
        },
        "Lazarus": {
            "tags": {
                "North Korea",
                "DPRK",
                "financial",
                "cryptocurrency",
                "Lazarus",
                "HIDDEN COBRA",
            },
            "techniques": ["T1133", "T1190", "T1486"],
            "group": "Lazarus Group",
            "region": "Global, Financial Sector",
            "motive": "Financial Gain, Sanctions Evasion",
            "summary": "Lazarus Group is a North Korean state-sponsored threat actor known for financial theft, cryptocurrency heists, and destructive attacks.",
        },
        # More groups would be defined here
    }

    # Convert reports and pulse names to tags for better matching
    combined_text = " ".join(all_reports + pulse_names).lower()

    # Extract potential APT indicators from text
    for _apt_name, apt_info in apt_patterns.items():
        for tag in apt_info["tags"]:
            if tag.lower() in combined_text:
                all_tags.add(tag)

    # Simple matching algorithm based on tag overlap
    best_match = None
    highest_score = 0
    for apt_name, apt_info in apt_patterns.items():
        overlap = len(all_tags.intersection(apt_info["tags"]))
        if overlap > highest_score:
            highest_score = overlap
            best_match = apt_name

    # Default attribution if no match found
    if not best_match or highest_score == 0:
        return APTAttribution(
            actor="Unknown",
            group="Unattributed",
            target_region="Unknown",
            target_sectors=["Unknown"],
            motive="Unknown",
            summary="Insufficient data for attribution",
            mitre_techniques=[],
            confidence=0,
        )

    # Get the matched APT data
    apt_data = apt_patterns[best_match]
    confidence = min(highest_score * 20, 100)  # Simple confidence calculation

    return APTAttribution(
        actor=best_match,
        group=apt_data["group"],
        target_region=apt_data["region"],
        target_sectors=[
            "Government",
            "Critical Infrastructure",
        ],  # Would be derived from actual data
        motive=apt_data["motive"],
        summary=apt_data["summary"],
        mitre_techniques=apt_data["techniques"],
        confidence=confidence,
    )


def create_stix_output(iocs: list[IOC], attribution: APTAttribution) -> dict[str, Any]:
    """Create a STIX-like JSON representation of the analyzed data."""
    timestamp = datetime.now().isoformat()

    # Create indicator objects for each IOC
    indicators = []
    for ioc in iocs:
        indicator = {
            "type": "indicator",
            "id": f"indicator--{hash(ioc.value)}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"{ioc.type.upper()}: {ioc.value}",
            "pattern": f"[{ioc.type}:value = '{ioc.value}']",
            "valid_from": timestamp,
            "labels": [ioc.reputation.lower()] if ioc.reputation else ["unknown"],
            "description": "; ".join(ioc.reports) if ioc.reports else "",
            "pattern_type": "stix",
        }
        indicators.append(indicator)

    # Create threat actor object if attribution is available
    threat_actors = []
    if attribution and attribution.actor and attribution.actor != "Unknown":
        threat_actor = {
            "type": "threat-actor",
            "id": f"threat-actor--{hash(attribution.actor)}",
            "created": timestamp,
            "modified": timestamp,
            "name": attribution.actor,
            "description": attribution.summary,
            "aliases": [attribution.group] if attribution.group else [],
            "threat_actor_types": ["state-sponsored"],
            "sophistication": "advanced",
            "resource_level": "government",
            "primary_motivation": attribution.motive.lower() if attribution.motive else "unknown",
        }
        threat_actors.append(threat_actor)

        # Create relationships between indicators and threat actor
        for _i, ioc in enumerate(iocs):
            relationship = {
                "type": "relationship",
                "id": f"relationship--{hash(ioc.value + attribution.actor)}",
                "created": timestamp,
                "modified": timestamp,
                "relationship_type": "attributed-to",
                "source_ref": f"indicator--{hash(ioc.value)}",
                "target_ref": f"threat-actor--{hash(attribution.actor)}",
                "description": f"This indicator is attributed to {attribution.actor}",
                "confidence": attribution.confidence,
            }
            indicators.append(relationship)

    # Combine all objects into a STIX bundle
    return {
        "type": "bundle",
        "id": f"bundle--{hash(timestamp)}",
        "objects": indicators + threat_actors,
    }


def _merge_ioc_results(ioc_value: str, ioc_type: str, source_iocs: list[IOC]) -> IOC:
    """Merges multiple IOC data points from different sources into a single IOC object."""
    if not source_iocs:
        return IOC(
            value=ioc_value,
            type=ioc_type,
            reputation="Unknown",
            score=None,
            abuseipdb_confidence=None,
            first_seen=None,
            last_seen=None,
            city=None,
            region=None,
            country=None,
            asn=None,
            location=None,
        )

    # Determine overall reputation, ignoring purely informational sources
    reputations = [
        r.reputation for r in source_iocs if r.reputation and r.reputation != "Informational"
    ]
    if "Malicious" in reputations:
        reputation = "Malicious"
    elif "Suspicious" in reputations:
        reputation = "Suspicious"
    elif reputations and all(r == "Clean" for r in reputations):
        reputation = "Clean"
    else:
        reputation = "Unknown"

    # Calculate aggregate score if available
    scores = [r.score for r in source_iocs if r.score is not None]
    score = sum(scores) / len(scores) if scores else None

    # Combine all reports, engines, and tags
    all_reports = []
    all_engines = []
    all_tags = set()
    otx_pulses = []
    abuseipdb_confidence = None

    for r in source_iocs:
        all_reports.extend(r.reports or [])
        all_engines.extend(r.engines or [])
        all_tags.update(r.tags or [])
        otx_pulses.extend(r.otx_pulses or [])
        if r.abuseipdb_confidence is not None:
            abuseipdb_confidence = r.abuseipdb_confidence

    # Get earliest first_seen and latest last_seen
    first_seen_dates = [r.first_seen for r in source_iocs if r.first_seen]
    last_seen_dates = [r.last_seen for r in source_iocs if r.last_seen]

    first_seen = min(first_seen_dates) if first_seen_dates else None
    last_seen = max(last_seen_dates) if last_seen_dates else None

    # Extract geolocation data
    city = next((r.city for r in source_iocs if r.city), None)
    region = next((r.region for r in source_iocs if r.region), None)
    country = next((r.country for r in source_iocs if r.country), None)
    asn = next((r.asn for r in source_iocs if r.asn), None)
    location = next((r.location for r in source_iocs if r.location), None)

    return IOC(
        value=ioc_value,
        type=ioc_type,
        reputation=reputation,
        score=round(score, 1) if score is not None else None,
        engines=list(set(all_engines)),
        reports=list(set(all_reports)),
        otx_pulses=list(set(otx_pulses)),
        abuseipdb_confidence=abuseipdb_confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        tags=list(all_tags),
        city=city,
        region=region,
        country=country,
        asn=asn,
        location=location,
    )


async def _analyze_iocs_impl(
    ioc_string: str | None = None,
    iocs: list[dict] | None = None,
    output_format: str = "markdown",
    include_stix: bool = True,
    include_graph: bool = True,
    ctx: Context | None = None,
) -> str:
    """
    Internal implementation of IOC analysis.

    Args:
        ioc_string: A single IOC string to analyze (alternative to iocs parameter)
        iocs: A list of IOC dictionaries with 'value' and optional 'type' fields
        output_format: Output format - 'markdown' (default), 'html', or 'json'
        include_stix: Whether to include STIX output in the report (default: True)
        include_graph: Whether to include network graph in the report (default: True)
        ctx: The MCP context

    Returns:
        A report with IOC analysis in the specified format
    """
    start_time = datetime.now()

    if ctx is None:
        raise ValueError("Context is required for this operation")

    if not await check_api_keys(ctx):
        return "Error: No API keys configured. Please configure at least one API key."

    await ctx.info("Starting IOC analysis")

    # --- IOC Parsing and Validation ---
    indicators_to_process = []
    if isinstance(iocs, list):
        indicators_to_process.extend(iocs)
    if isinstance(ioc_string, str) and ioc_string.strip():
        ioc_values = re.split(r"[\s,;\n]+", ioc_string.strip())
        indicators_to_process.extend([{"value": v.strip()} for v in ioc_values if v.strip()])

    if not indicators_to_process:
        await ctx.error("No valid IOCs provided for analysis")
        return "Error: Please provide at least one IOC for analysis."

    # --- Parallel API Queries ---
    all_tasks = []
    valid_iocs_map = {}  # Map ioc_value to ioc_type

    for entry in indicators_to_process:
        ioc_value = entry.get("value") if isinstance(entry, dict) else str(entry)
        if not ioc_value or ioc_value in valid_iocs_map:
            continue

        ioc_type = await get_ioc_type(ioc_value, ctx)
        if ioc_type == "unknown":
            await ctx.warning(f"Skipping IOC with unknown type: {ioc_value}")
            continue

        valid_iocs_map[ioc_value] = ioc_type
        all_tasks.append(query_virustotal(ioc_value, ioc_type, ctx=ctx))
        all_tasks.append(query_otx(ioc_value, ioc_type, ctx=ctx))
        if ioc_type.lower() == "ip":
            all_tasks.append(query_abuseipdb(ioc_value, ioc_type, ctx=ctx))
            all_tasks.append(query_ipinfo(ioc_value, ioc_type, ctx=ctx))

    await ctx.info(f"Gathered {len(all_tasks)} API calls for {len(valid_iocs_map)} IOCs.")

    # --- Merge and Consolidate Results ---
    raw_results = []
    if all_tasks:
        raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)

    grouped_results = {ioc_value: [] for ioc_value in valid_iocs_map}
    for result in raw_results:
        # First, check if the result is an exception and log it.
        if isinstance(result, Exception):
            await ctx.error(f"An API query failed: {str(result)}")
            continue
        # If it's a valid IOC object, group it by its value.
        if isinstance(result, IOC) and result.value in grouped_results:
            grouped_results[result.value].append(result)

    processed_iocs = []
    for ioc_value, source_iocs in grouped_results.items():
        ioc_type = valid_iocs_map[ioc_value]
        if source_iocs:
            merged_ioc = _merge_ioc_results(ioc_value, ioc_type, source_iocs)
            processed_iocs.append(merged_ioc)

    if not processed_iocs:
        return "Error: No valid IOCs could be processed. Check your input or API keys."

    attribution = await determine_attribution(processed_iocs, ctx)

    # Generate the report
    try:
        report_id = datetime.now().strftime("%Y%m%d%H%M%S")
        elapsed_time = (datetime.now() - start_time).total_seconds()

        # Create visualizations based on flags
        table = create_ioc_table(processed_iocs)

        network_graph = None
        if include_graph:
            network_graph = create_network_graph(processed_iocs, attribution)

        stix = None
        if include_stix:
            stix = create_stix_output(processed_iocs, attribution)

        # Generate HTML report regardless of format choice for saving
        html_report = create_interactive_report(
            processed_iocs, attribution, report_id, include_graph=include_graph
        )

        # Save HTML report to temp directory
        temp_dir = tempfile.gettempdir()
        report_filename = os.path.join(temp_dir, f"ioc_report_{report_id}.html")

        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report)

        await ctx.info(f"Interactive HTML report saved to {report_filename}")

        # The tool's responsibility is to provide the path.
        # The client (e.g., the VS Code extension) is responsible for opening it.
        # The webbrowser.open call is removed as it won't work in a server environment.

        # Return based on requested format
        if output_format.lower() == "json":
            # Return JSON output
            json_output = {
                "summary": {
                    "total_iocs": len(processed_iocs),
                    "malicious_iocs": sum(
                        1 for ioc in processed_iocs if ioc.reputation == "Malicious"
                    ),
                    "suspicious_iocs": sum(
                        1 for ioc in processed_iocs if ioc.reputation == "Suspicious"
                    ),
                    "clean_iocs": sum(1 for ioc in processed_iocs if ioc.reputation == "Clean"),
                    "report_id": report_id,
                    "report_time": datetime.now().isoformat(),
                    "elapsed_time": elapsed_time,
                },
                "iocs": [ioc.dict() for ioc in processed_iocs],
                "attribution": attribution.dict() if attribution else None,
                "html_report_path": report_filename,
            }

            if include_graph:
                json_output["network_graph"] = network_graph

            if include_stix:
                json_output["stix"] = stix

            return json.dumps(json_output, indent=2)

        elif output_format.lower() == "html":
            # Return the HTML report directly
            return html_report

        else:  # Default to markdown
            # Create markdown report
            report = f"""
# IOC Analysis Report

## Summary
- **Total IOCs Analyzed**: {len(processed_iocs)}
- **Malicious IOCs**: {sum(1 for ioc in processed_iocs if ioc.reputation == "Malicious")}
- **Suspicious IOCs**: {sum(1 for ioc in processed_iocs if ioc.reputation == "Suspicious")}
- **Clean IOCs**: {sum(1 for ioc in processed_iocs if ioc.reputation == "Clean")}
- **Report ID**: {report_id}
- **Report Time**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Processing Time**: {elapsed_time:.2f} seconds

## IOC Table
{table}
"""

            # Add network graph if requested
            if include_graph and network_graph:
                report += f"""
## Network Graph (D3 JSON)
```json
{json.dumps(network_graph)}
```
"""

            # Add attribution details if available
            if attribution:
                report += f"""
## APT Attribution & Summary
- **APT Actor Identified**: {attribution.actor}
- **Associated Group**: {attribution.group}
- **Target Region**: {attribution.target_region}
- **Motive**: {attribution.motive}
- **Attribution Confidence**: {attribution.confidence}%
- **MITRE ATT&CK Techniques**: {", ".join(attribution.mitre_techniques)}
- **Summary**: {attribution.summary}
"""

            # Add STIX output if requested
            if include_stix and stix:
                report += f"""
## STIX-like JSON Output
```json
{json.dumps(stix, indent=2)}
```
"""

            # Add link to interactive report
            report += f"""
## Interactive Report
An interactive HTML report has been saved to `{report_filename}`.
"""
            return report

    except Exception as e:
        await ctx.error(f"Error generating report: {str(e)}")
        return f"Error generating report: {str(e)}"


def register_tools(mcp: FastMCP):
    """Registers the tools with the MCP server."""

    @mcp.tool()
    async def analyze_iocs(
        ioc_string: str | None = None,
        iocs: list[dict] | None = None,
        output_format: str = "markdown",
        include_stix: bool = True,
        include_graph: bool = True,
        ctx: Context | None = None,
    ) -> str:
        """
        Analyze IOCs (Indicators of Compromise) using multiple threat intelligence sources.

        Args:
            ioc_string: A single IOC string to analyze (alternative to iocs parameter)
            iocs: A list of IOC dictionaries with 'value' and optional 'type' fields
            output_format: Output format - 'markdown' (default), 'html', or 'json'
            include_stix: Whether to include STIX output in the report (default: True)
            include_graph: Whether to include network graph in the report (default: True)
            ctx: The MCP context

        Returns:
            A report with IOC analysis in the specified format
        """
        return await _analyze_iocs_impl(
            ioc_string, iocs, output_format, include_stix, include_graph, ctx
        )
