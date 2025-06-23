#!/usr/bin/env python3
"""
CLI module for standalone threat intelligence analysis.
Provides interactive, batch, and MCP server modes.
"""

import asyncio
import json
import logging
import sys
import tempfile
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from .server import configure_logging, create_server
from .settings import settings
from .tools import _analyze_iocs_impl, get_ioc_type, process_single_ioc

# Initialize Rich console
console = Console()
app = typer.Typer(
    name="threatintel",
    help="🛡️ FastMCP ThreatIntel - MCP AI Powered Threat Intelligence, Revolutionizing Cybersecurity | Built by Arjun Trivedi (4R9UN)",
    rich_markup_mode="rich",
)


class MockContext:
    """Mock context for standalone CLI usage."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger("threatintel.cli")

    async def info(self, message: str):
        if self.verbose:
            console.print(f"[blue]ℹ️ {message}[/blue]")
        self.logger.info(message)

    async def warning(self, message: str):
        console.print(f"[yellow]⚠️ {message}[/yellow]")
        self.logger.warning(message)

    async def error(self, message: str):
        console.print(f"[red]❌ {message}[/red]")
        self.logger.error(message)

    async def debug(self, message: str):
        if self.verbose:
            console.print(f"[dim]🐛 {message}[/dim]")
        self.logger.debug(message)


def display_banner(console_obj: Console = console):
    """Display the application banner."""
    banner = """
    [bold blue]🛡️ FastMCP ThreatIntel[/bold blue]
    [dim]MCP AI Powered Threat Intelligence - Revolutionizing Cybersecurity[/dim]
    [dim italic]Built by Arjun Trivedi (4R9UN)[/dim italic]
    """
    console_obj.print(Panel(banner, expand=False))


def check_api_configuration(console_obj: Console = console) -> bool:
    """Check if API keys are configured and warn if missing."""
    missing_keys = []

    if not settings.virustotal_api_key:
        missing_keys.append("VirusTotal")
    if not settings.otx_api_key:
        missing_keys.append("OTX")
    if not settings.abuseipdb_api_key:
        missing_keys.append("AbuseIPDB")

    if missing_keys:
        console_obj.print(f"[yellow]⚠️ Missing API keys: {', '.join(missing_keys)}[/yellow]")
        console_obj.print(
            "[dim]Some features may be limited. Configure API keys for full functionality.[/dim]"
        )
        return len(missing_keys) < 3

    console_obj.print("[green]✅ All API keys configured[/green]")
    return True


@app.command()
def version():
    """Show version information."""
    console.print("[bold blue]🛡️ FastMCP ThreatIntel v0.2.7[/bold blue]")
    console.print("[dim]MCP AI Powered Threat Intelligence - Revolutionizing Cybersecurity[/dim]")
    console.print(
        "[dim italic]Built by Arjun Trivedi (4R9UN) with ❤️ for the cybersecurity community[/dim italic]"
    )
    console.print("\n[bold]License:[/bold] Apache-2.0")
    console.print("[bold]Repository:[/bold] https://github.com/4R9UN/fastmcp-threatintel")
    console.print("[bold]Documentation:[/bold] https://4r9un.github.io/fastmcp-threatintel/")


@app.command()
def config():
    """Show current configuration and help with setup."""
    display_banner()

    console.print("[bold]Current Configuration:[/bold]")

    # API Keys status
    table = Table(title="API Keys Status")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Required", style="yellow")

    table.add_row(
        "VirusTotal", "✅ Configured" if settings.virustotal_api_key else "❌ Missing", "Yes"
    )
    table.add_row("OTX", "✅ Configured" if settings.otx_api_key else "❌ Missing", "Yes")
    table.add_row(
        "AbuseIPDB", "✅ Configured" if settings.abuseipdb_api_key else "❌ Missing", "No"
    )
    table.add_row("IPinfo", "✅ Configured" if settings.ipinfo_api_key else "❌ Missing", "No")

    console.print(table)

    # Performance settings
    console.print("\n[bold]Performance Settings:[/bold]")
    perf_table = Table()
    perf_table.add_column("Setting", style="cyan")
    perf_table.add_column("Value", style="green")

    perf_table.add_row("Max Retries", str(settings.max_retries))
    perf_table.add_row("Request Timeout", f"{settings.request_timeout}s")
    perf_table.add_row("Cache TTL", f"{settings.cache_ttl}s")

    console.print(perf_table)

    # Configuration help
    console.print("\n[bold]Configuration Help:[/bold]")
    console.print("Create a [cyan].env[/cyan] file in your project directory with:")
    console.print("""
[dim]VIRUSTOTAL_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_otx_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
IPINFO_API_KEY=your_ipinfo_api_key[/dim]
    """)


@app.command()
def server(
    log_level: str = typer.Option("INFO", help="Logging level"),
    host: str = typer.Option("localhost", help="Host to bind to"),
    port: int = typer.Option(8000, help="Port to bind to"),
):
    """Start the MCP server."""
    configure_logging(log_level)

    # For server mode, all non-JSON-RPC output must go to stderr to avoid
    # corrupting the communication channel with the MCP client.
    stderr_console = Console(file=sys.stderr)
    check_api_configuration(console_obj=stderr_console)

    stderr_console.print(f"[green]🚀 Starting MCP server on {host}:{port}[/green]")

    try:
        server = create_server()
        server.run()
    except Exception as e:
        stderr_console.print(f"[red]❌ Server failed to start: {str(e)}[/red]")
        raise typer.Exit(1) from e


@app.command()
def analyze(
    ioc: str = typer.Argument(..., help="IOC to analyze (IP, domain, URL, or hash)"),
    output_format: str = typer.Option("table", help="Output format: table, json, markdown, html"),
    save_report: bool = typer.Option(False, help="Save HTML report to file"),
    open_browser: bool = typer.Option(False, help="Open report in browser"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """Analyze a single IOC."""
    if not check_api_configuration():
        raise typer.Exit(1)

    async def _analyze():
        ctx = MockContext(verbose=verbose)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing IOC...", total=None)

            try:
                # Auto-detect IOC type
                ioc_type = await get_ioc_type(ioc, ctx)  # type: ignore
                if ioc_type == "unknown":
                    console.print(f"[red]❌ Could not determine IOC type for: {ioc}[/red]")
                    return

                progress.update(task, description=f"Processing {ioc_type.upper()}: {ioc}")

                # Process the IOC
                result = await process_single_ioc(ioc, ioc_type, ctx)  # type: ignore

                progress.update(task, description="Generating report...")

                # Display results based on format
                if output_format.lower() == "table":
                    # Create and display Rich table
                    table = Table(title=f"IOC Analysis: {ioc}")
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="green")

                    table.add_row("IOC", result.value)
                    table.add_row("Type", result.type.upper())
                    table.add_row("Reputation", result.reputation or "Unknown")
                    table.add_row("Score", f"{result.score:.1f}" if result.score else "N/A")

                    if result.engines:
                        table.add_row("Detection Engines", f"{len(result.engines)} engines")

                    if result.reports:
                        table.add_row("Reports", "; ".join(result.reports[:3]))

                    if result.city or result.country:
                        location = (
                            f"{result.city}, {result.country}"
                            if result.city and result.country
                            else result.country or result.city
                        )
                        table.add_row("Location", location)

                    console.print(table)

                elif output_format.lower() == "json":
                    console.print(json.dumps(result.dict(), indent=2))

                elif output_format.lower() in ["markdown", "html"]:
                    report = await _analyze_iocs_impl(
                        ioc_string=ioc,
                        output_format=output_format,
                        include_stix=True,
                        include_graph=True,
                        ctx=ctx,  # type: ignore
                    )

                    if output_format.lower() == "html" and (save_report or open_browser):
                        # Save HTML to file
                        temp_dir = tempfile.gettempdir()
                        filename = (
                            Path(temp_dir)
                            / f"threatintel_report_{ioc.replace('.', '_').replace('/', '_')}.html"
                        )

                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(report)

                        console.print(f"[green]📄 Report saved to: {filename}[/green]")

                        if open_browser:
                            webbrowser.open(f"file://{filename}")
                            console.print("[green]🌐 Report opened in browser[/green]")
                    else:
                        console.print(report)

            except Exception as e:
                console.print(f"[red]❌ Analysis failed: {str(e)}[/red]")

    asyncio.run(_analyze())


@app.command()
def batch(
    input_file: str = typer.Argument(..., help="File containing IOCs (one per line)"),
    output_file: str | None = typer.Option(None, help="Output file for results"),
    output_format: str = typer.Option("markdown", help="Output format: markdown, json, html"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """Analyze IOCs from a file in batch mode."""
    if not check_api_configuration():
        raise typer.Exit(1)

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[red]❌ Input file not found: {input_file}[/red]")
        raise typer.Exit(1)

    async def _batch_analyze():
        ctx = MockContext(verbose=verbose)

        # Read IOCs from file
        try:
            with open(input_path, encoding="utf-8") as f:
                iocs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"[red]❌ Error reading file: {str(e)}[/red]")
            return

        if not iocs:
            console.print("[yellow]⚠️ No IOCs found in file[/yellow]")
            return

        console.print(f"[blue]📊 Processing {len(iocs)} IOCs from {input_file}[/blue]")

        with Progress(console=console) as progress:
            progress.add_task("Analyzing IOCs...", total=len(iocs))

            try:
                # Use the main analysis function
                report = await _analyze_iocs_impl(
                    iocs=[{"value": ioc} for ioc in iocs],
                    output_format=output_format,
                    include_stix=True,
                    include_graph=True,
                    ctx=ctx,  # type: ignore
                )

                # Save or display results
                if output_file:
                    output_path = Path(output_file)
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(report)
                    console.print(f"[green]📄 Report saved to: {output_file}[/green]")
                else:
                    console.print(report)

            except Exception as e:
                console.print(f"[red]❌ Batch analysis failed: {str(e)}[/red]")

    asyncio.run(_batch_analyze())


@app.command()
def interactive(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """Start an interactive REPL session for IOC analysis."""
    display_banner()

    if not check_api_configuration():
        if not Confirm.ask("Continue with limited functionality?"):
            raise typer.Exit(1)

    console.print("[green]🔍 Interactive Mode Started[/green]")
    console.print("[dim]Type 'help' for commands, 'exit' to quit[/dim]\n")

    async def _interactive():
        ctx = MockContext(verbose=verbose)

        while True:
            try:
                command = Prompt.ask("[bold cyan]threatintel>[/bold cyan]").strip()

                if command.lower() in ["exit", "quit", "q"]:
                    console.print("[yellow]👋 Goodbye![/yellow]")
                    break

                elif command.lower() in ["help", "h"]:
                    console.print(
                        """
[bold]Available Commands:[/bold]
• [cyan]<ioc>[/cyan] - Analyze an IOC (IP, domain, URL, hash)
• [cyan]batch <file>[/cyan] - Analyze IOCs from file
• [cyan]config[/cyan] - Show configuration
• [cyan]help[/cyan] - Show this help
• [cyan]exit[/cyan] - Exit interactive mode
                    """
                    )

                elif command.lower() == "config":
                    check_api_configuration()

                elif command.startswith("batch "):
                    filename = command[6:].strip()
                    console.print(f"[blue]📊 Processing batch file: {filename}[/blue]")
                    # Could implement batch processing here

                elif command:
                    # Treat as IOC to analyze
                    ioc_type = await get_ioc_type(command, ctx)  # type: ignore
                    if ioc_type == "unknown":
                        console.print(f"[red]❌ Could not determine IOC type for: {command}[/red]")
                        continue

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        progress.add_task(f"Analyzing {ioc_type.upper()}...", total=None)

                        result = await process_single_ioc(command, ioc_type, ctx)  # type: ignore

                        # Display simple table
                        table = Table()
                        table.add_column("Property", style="cyan")
                        table.add_column("Value", style="green")

                        table.add_row("IOC", result.value)
                        table.add_row("Type", result.type.upper())
                        table.add_row("Reputation", result.reputation or "Unknown")
                        table.add_row("Score", f"{result.score:.1f}" if result.score else "N/A")

                        console.print(table)

            except KeyboardInterrupt:
                console.print("\n[yellow]👋 Goodbye![/yellow]")
                break
            except Exception as e:
                console.print(f"[red]❌ Error: {str(e)}[/red]")

    asyncio.run(_interactive())


@app.command()
def setup():
    """Interactive setup wizard for API keys and configuration."""
    display_banner()

    console.print("[bold]🔧 Configuration Setup Wizard[/bold]\n")

    # Check if .env file exists
    env_file = Path(".env")
    if env_file.exists():
        if not Confirm.ask(".env file already exists. Overwrite?"):
            console.print("[yellow]Setup cancelled[/yellow]")
            return

    console.print("Let's configure your API keys.\n")

    # Collect API keys
    api_keys = {}

    console.print("[bold cyan]VirusTotal API Key[/bold cyan] (Required)")
    console.print("Get it from: https://www.virustotal.com/gui/join-us")
    vt_key = Prompt.ask("VirusTotal API Key", default="")
    if vt_key:
        api_keys["VIRUSTOTAL_API_KEY"] = vt_key

    console.print("\n[bold cyan]OTX API Key[/bold cyan] (Required)")
    console.print("Get it from: https://otx.alienvault.com/")
    otx_key = Prompt.ask("OTX API Key", default="")
    if otx_key:
        api_keys["OTX_API_KEY"] = otx_key

    console.print("\n[bold cyan]AbuseIPDB API Key[/bold cyan] (Optional)")
    console.print("Get it from: https://www.abuseipdb.com/register")
    abuse_key = Prompt.ask("AbuseIPDB API Key", default="")
    if abuse_key:
        api_keys["ABUSEIPDB_API_KEY"] = abuse_key

    console.print("\n[bold cyan]IPinfo API Key[/bold cyan] (Optional)")
    console.print("Get it from: https://ipinfo.io/signup")
    ipinfo_key = Prompt.ask("IPinfo API Key", default="")
    if ipinfo_key:
        api_keys["IPINFO_API_KEY"] = ipinfo_key

    # Write .env file
    try:
        with open(env_file, "w") as f:
            f.write("# FastMCP ThreatIntel Configuration\n")
            f.write("# Generated by setup wizard\n\n")

            for key, value in api_keys.items():
                f.write(f"{key}={value}\n")

            f.write("\n# Performance Settings\n")
            f.write("CACHE_TTL=3600\n")
            f.write("MAX_RETRIES=3\n")
            f.write("REQUEST_TIMEOUT=30\n")

        console.print(f"\n[green]✅ Configuration saved to {env_file}[/green]")
        console.print("[dim]You can now use threatintel commands![/dim]")

    except Exception as e:
        console.print(f"[red]❌ Error saving configuration: {str(e)}[/red]")


def main():
    """Main entry point for the CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
