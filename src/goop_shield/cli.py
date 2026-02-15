# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Brian Taylor
"""
goop-shield CLI

Manage the Shield runtime defense service.

Usage:
    goop-shield serve --port 8787
    goop-shield status
    goop-shield test --url http://localhost:8787
    goop-shield update --weights-file weights.json
    goop-shield mcp
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer(
    name="goop-shield",
    help="Runtime defense for AI agents",
)


@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    """goop-shield — Runtime defense for AI agents."""
    if ctx.invoked_subcommand is not None:
        return
    console.print("[bold]goop-shield[/bold] — Runtime defense for AI agents")
    console.print("Use [cyan]goop-shield --help[/cyan] for available commands")


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option("--host", "-h", help="Host to bind to")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind to")] = 8787,
    workers: Annotated[int, typer.Option("--workers", "-w", help="Number of workers")] = 1,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", help="Shield config YAML")
    ] = None,
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="SHIELD_API_KEY", help="API key")
    ] = None,
    log_level: Annotated[str, typer.Option("--log-level", "-l", help="Logging level")] = "info",
    reload: Annotated[bool, typer.Option("--reload", help="Enable auto-reload")] = False,
):
    """Start the Shield defense server."""
    import os

    console.print("[bold blue]goop-shield Server[/bold blue]")
    console.print(f"  Host:    {host}")
    console.print(f"  Port:    {port}")
    console.print(f"  Workers: {workers}")
    console.print(f"  Auth:    {'enabled' if api_key else 'disabled'}")
    console.print()

    valid_log_levels = {"debug", "info", "warning", "error", "critical"}
    if log_level.lower() not in valid_log_levels:
        console.print(f"[red]Invalid log level: {log_level}[/red]")
        raise typer.Exit(1)

    if config is not None:
        os.environ["SHIELD_CONFIG"] = str(config)
    if api_key is not None:
        os.environ["SHIELD_API_KEY"] = api_key

    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]uvicorn not installed. Install with: pip install goop-shield[server][/red]"
        )
        raise typer.Exit(1)

    try:
        logging.basicConfig(level=getattr(logging, log_level.upper()))
        console.print(f"[green]Starting Shield at http://{host}:{port}[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")
        console.print()

        uvicorn.run(
            "goop_shield.app:app",
            host=host,
            port=port,
            workers=1 if reload else workers,
            reload=reload,
            log_level=log_level.lower(),
        )
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        raise typer.Exit(1)


@app.command("status")
def status(
    url: Annotated[
        str, typer.Option("--url", "-u", help="Shield server URL")
    ] = "http://localhost:8787",
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="SHIELD_API_KEY", help="API key")
    ] = None,
):
    """Check Shield server health status."""
    import httpx

    console.print(f"Checking Shield at {url}...")

    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        response = httpx.get(f"{url}/api/v1/health", timeout=5.0, headers=headers)
        if response.status_code == 200:
            data = response.json()
            table = Table(title="Shield Status")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Status", f"[green]{data.get('status', 'unknown')}[/green]")
            table.add_row("Version", data.get("version", "unknown"))
            table.add_row("Defenses", str(data.get("defenses_loaded", 0)))
            table.add_row("Scanners", str(data.get("scanners_loaded", 0)))
            table.add_row(
                "BroRL",
                "[green]ready[/green]" if data.get("brorl_ready") else "[yellow]not ready[/yellow]",
            )
            table.add_row("Uptime", f"{data.get('uptime_seconds', 0):.0f}s")
            table.add_row("Requests", str(data.get("total_requests", 0)))
            table.add_row("Blocked", str(data.get("total_blocked", 0)))
            console.print(table)
        else:
            console.print(f"[yellow]Server returned status {response.status_code}[/yellow]")
    except httpx.ConnectError:
        console.print(f"[red]Could not connect to {url}[/red]")
        console.print("Start Shield with: goop-shield serve")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("test")
def test(
    url: Annotated[
        str, typer.Option("--url", "-u", help="Shield server URL")
    ] = "http://localhost:8787",
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="SHIELD_API_KEY", help="API key")
    ] = None,
):
    """Run red-team probe suite against Shield."""
    import httpx

    console.print(f"Running red-team probes against {url}...")
    console.print()

    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        response = httpx.post(
            f"{url}/api/v1/redteam/probe",
            json={"probe_names": None},
            timeout=60.0,
            headers=headers,
        )
        if response.status_code == 200:
            data = response.json()
            table = Table(title="Red Team Probe Results")
            table.add_column("Probe", style="cyan")
            table.add_column("Target", style="white")
            table.add_column("Blocked", style="white")
            table.add_column("Bypassed", style="white")
            table.add_column("Caught By", style="white")
            table.add_column("Confidence", style="white")

            for result in data.get("results", []):
                blocked = "[green]Yes[/green]" if result.get("payload_blocked") else "[red]No[/red]"
                bypassed = (
                    "[red]Yes[/red]" if result.get("defense_bypassed") else "[green]No[/green]"
                )
                table.add_row(
                    result.get("probe_name", ""),
                    result.get("target_defense", ""),
                    blocked,
                    bypassed,
                    result.get("caught_by") or "-",
                    f"{result.get('confidence', 0):.2f}",
                )

            console.print(table)
            console.print()
            console.print(f"Total probes: {data.get('total_probes', 0)}")
            console.print(f"Bypasses: {data.get('defenses_bypassed', 0)}")
            bypass_rate = data.get("bypass_rate", 0)
            color = "green" if bypass_rate == 0 else ("yellow" if bypass_rate < 0.3 else "red")
            console.print(f"Bypass rate: [{color}]{bypass_rate:.1%}[/{color}]")
        elif response.status_code == 404:
            console.print("[yellow]Red team not enabled on this Shield instance[/yellow]")
            console.print("Enable with: use_redteam: true in config")
        else:
            console.print(f"[red]Server returned status {response.status_code}[/red]")
    except httpx.ConnectError:
        console.print(f"[red]Could not connect to {url}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("update")
def update(
    url: Annotated[
        str, typer.Option("--url", "-u", help="Shield server URL")
    ] = "http://localhost:8787",
    weights_file: Annotated[
        Path | None, typer.Option("--weights-file", "-f", help="BroRL weights JSON file")
    ] = None,
    api_key: Annotated[
        str | None, typer.Option("--api-key", envvar="SHIELD_API_KEY", help="API key")
    ] = None,
):
    """Update BroRL weights on a running Shield instance."""
    import httpx

    if weights_file is None:
        console.print("[red]Provide --weights-file with path to BroRL weights JSON[/red]")
        raise typer.Exit(1)

    if not weights_file.exists():
        console.print(f"[red]File not found: {weights_file}[/red]")
        raise typer.Exit(1)

    try:
        weights = json.loads(weights_file.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON: {e}[/red]")
        raise typer.Exit(1)

    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        response = httpx.post(
            f"{url}/api/v1/brorl/load",
            json=weights,
            timeout=10.0,
            headers=headers,
        )
        if response.status_code == 200:
            console.print("[green]BroRL weights updated successfully[/green]")
        else:
            console.print(f"[red]Failed to update weights: {response.status_code}[/red]")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print(f"[red]Could not connect to {url}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("mcp")
def mcp_command(
    config: Annotated[
        str | None, typer.Option("--config", "-c", help="Shield config YAML path")
    ] = None,
):
    """Run Shield as an MCP server (stdio transport).

    For use with MCP-capable AI agents like Claude Code, Cursor, etc.
    Add to your agent's MCP config:

        {"mcpServers": {"goop-shield": {"command": "goop-shield", "args": ["mcp"]}}}
    """
    import asyncio

    try:
        from goop_shield.mcp import run_server
    except ImportError:
        console.print("[red]MCP support requires the 'mcp' package.[/red]")
        console.print("Install with: pip install goop-shield[mcp]")
        raise typer.Exit(1)

    asyncio.run(run_server(config_path=config))


def main():
    """Entry point for the goop-shield CLI."""
    app()


if __name__ == "__main__":
    main()
