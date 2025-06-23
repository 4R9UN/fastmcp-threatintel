import asyncio
import logging
import os
import sys

import typer
from fastmcp import Context, FastMCP

from .settings import settings
from .tools import analyze_iocs_from_file, process_single_ioc, register_tools

# Create a logger
logger = logging.getLogger("threatintel")


def configure_logging(log_level: str = "INFO"):
    """Configure logging for the application."""
    level = getattr(logging, log_level.upper())
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    logger.setLevel(level)


def create_server():
    """Create and configure the MCP server with all tools registered."""
    try:
        mcp = FastMCP("ThreatIntel")
        register_tools(mcp)
        logger.info("ThreatIntel MCP server created and tools registered successfully")
        return mcp
    except Exception as e:
        logger.error(f"Failed to create MCP server: {str(e)}")
        raise


app = typer.Typer(help="ThreatIntel MCP Server - Analyze IOCs using threat intelligence services")


def _override_api_keys(
    vt_api_key: str | None,
    otx_api_key: str | None,
    abuseipdb_api_key: str | None,
):
    """Override API keys from CLI options."""
    if vt_api_key:
        os.environ["VIRUSTOTAL_API_KEY"] = vt_api_key
        settings.virustotal_api_key = vt_api_key

    if otx_api_key:
        os.environ["OTX_API_KEY"] = otx_api_key
        settings.otx_api_key = otx_api_key

    if abuseipdb_api_key:
        os.environ["ABUSEIPDB_API_KEY"] = abuseipdb_api_key
        settings.abuseipdb_api_key = abuseipdb_api_key


@app.command()
def run(
    log_level: str = typer.Option("INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)"),
    vt_api_key: str | None = typer.Option(None, help="VirusTotal API key (overrides environment)"),
    otx_api_key: str | None = typer.Option(None, help="OTX API key (overrides environment)"),
    abuseipdb_api_key: str | None = typer.Option(
        None, help="AbuseIPDB API key (overrides environment)"
    ),
):
    """Run the ThreatIntel MCP server."""
    configure_logging(log_level)
    _override_api_keys(vt_api_key, otx_api_key, abuseipdb_api_key)

    logger.info("Starting ThreatIntel MCP server")
    try:
        server = create_server()
        server.run()
    except Exception as e:
        logger.critical(f"Server failed to start: {str(e)}")
        sys.exit(1)


@app.command()
def batch(
    file_path: str = typer.Argument(..., help="Path to the file containing IOCs (one per line)"),
    log_level: str = typer.Option("INFO", help="Logging level"),
    vt_api_key: str | None = typer.Option(None, help="VirusTotal API key"),
    otx_api_key: str | None = typer.Option(None, help="OTX API key"),
    abuseipdb_api_key: str | None = typer.Option(None, help="AbuseIPDB API key"),
):
    """Analyze IOCs from a file in batch mode."""
    configure_logging(log_level)
    _override_api_keys(vt_api_key, otx_api_key, abuseipdb_api_key)

    async def _run_batch():
        # Create a mock context for standalone use
        mock_ctx = Context(server=None, tool_name="batch")
        await analyze_iocs_from_file(file_path, mock_ctx)

    asyncio.run(_run_batch())


@app.command()
def interactive(
    log_level: str = typer.Option("INFO", help="Logging level"),
    vt_api_key: str | None = typer.Option(None, help="VirusTotal API key"),
    otx_api_key: str | None = typer.Option(None, help="OTX API key"),
    abuseipdb_api_key: str | None = typer.Option(None, help="AbuseIPDB API key"),
):
    """Start an interactive REPL session for IOC analysis."""
    configure_logging(log_level)
    _override_api_keys(vt_api_key, otx_api_key, abuseipdb_api_key)

    async def _run_interactive():
        mock_ctx = Context(server=None, tool_name="interactive")
        typer.echo("ThreatIntel Interactive Mode. Type 'exit' to quit.")

        while True:
            ioc_string = typer.prompt("Enter IOC to analyze")
            if ioc_string.lower() == "exit":
                break

            # Create a mock context for each call
            from .tools import create_ioc_table, get_ioc_type

            ioc_type = await get_ioc_type(ioc_string, mock_ctx)
            if ioc_type != "unknown":
                result = await process_single_ioc(ioc_string, ioc_type, mock_ctx)
                typer.echo(create_ioc_table([result]))
            else:
                typer.echo(f"Could not determine IOC type for: {ioc_string}")

    asyncio.run(_run_interactive())


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
