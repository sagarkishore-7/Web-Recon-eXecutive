"""CLI entrypoint for WRX."""

from __future__ import annotations

import asyncio
import subprocess
import webbrowser
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wrx import __version__
from wrx.config import load_config, resolve_run_config
from wrx.diff import compute_workspace_diff
from wrx.exporters import render_export_payload
from wrx.preflight import (
    JUICE_SHOP_DOCKER_CMD,
    JUICE_SHOP_URL,
    check_juice_shop_reachable,
    run_doctor_checks,
    strict_failures,
)
from wrx.report import generate_report
from wrx.runner import RunResult, run_pipeline
from wrx.workspace import (
    current_run_id,
    ensure_workspace,
    init_workspace,
    list_completed_runs,
    mark_run_completed,
    read_json,
    start_or_resume_run,
    sync_latest_aliases,
)

app = typer.Typer(
    name="wrx",
    help=(
        "Web Recon eXecutive (WRX) - orchestrate common recon tools into one reproducible pipeline.\n\n"
        "Examples:\n"
        "  wrx init example.com\n"
        "  wrx run example.com --preset quick --dry-run\n"
        "  wrx doctor\n"
        "  wrx demo juice-shop\n"
        "  wrx gui --target juice-shop\n"
        "  wrx flow juice-shop --dry-run\n"
        "  wrx diff example.com --last 1\n"
        "  wrx report example.com\n"
        "  wrx export example.com --format sarif"
    ),
    add_completion=False,
)
console = Console()


def _print_banner() -> None:
    heading = Text()
    heading.append("WRX", style="bold cyan")
    heading.append("  |  Web Recon eXecutive", style="bold white")

    subtitle = Text(f"v{__version__}  •  Safe-by-default recon orchestration", style="dim")

    console.print(
        Panel(
            Text.assemble(heading, "\n", subtitle),
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )
    console.print("[bold yellow]Only scan targets you own or have permission to test.[/bold yellow]")


def _render_stage_table(rows: list[dict[str, Any]]) -> None:
    table = Table(title="WRX Stage Summary")
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Duration (s)", justify="right")
    table.add_column("Message")

    for row in rows:
        table.add_row(
            row["stage"],
            row["status"],
            f"{row['duration_seconds']:.2f}",
            row.get("message", ""),
        )

    console.print(table)


def _render_counts(summary: dict[str, Any]) -> None:
    counts = summary.get("counts", {})
    table = Table(title="WRX Run Totals")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    table.add_row("Subdomains", str(counts.get("subdomains", 0)))
    table.add_row("Alive Hosts", str(counts.get("alive_hosts", 0)))
    table.add_row("URLs", str(counts.get("urls", 0)))
    table.add_row("Nuclei Findings", str(counts.get("nuclei_findings", 0)))
    table.add_row("ZAP Findings", str(counts.get("zap_findings", 0)))
    console.print(table)


def _run_with_resolved_config(
    workspace: Path,
    pipeline_target: str,
    run_config: dict[str, Any],
    force: bool,
    dry_run: bool,
) -> tuple[str, RunResult, Optional[Path]]:
    resolved_concurrency = int(run_config.get("default_concurrency", 4))

    run_id, _, resumed = start_or_resume_run(workspace, force=force)
    if resumed:
        console.print(f"[yellow]Resuming in-progress run:[/yellow] {run_id}")
    else:
        console.print(f"[green]Started run:[/green] {run_id}")

    result = asyncio.run(
        run_pipeline(
            target=pipeline_target,
            workspace=workspace,
            run_id=run_id,
            run_config=run_config,
            concurrency=resolved_concurrency,
            force=force,
            dry_run=dry_run,
            console=console,
        )
    )

    mark_run_completed(workspace, run_id)
    sync_latest_aliases(workspace, run_id)

    report_path: Optional[Path] = None
    if run_config.get("stages", {}).get("report", True):
        report_path = generate_report(workspace, run_id=run_id)
        console.print(f"[green]Report generated:[/green] {report_path}")

    _render_stage_table(
        [
            {
                "stage": item.stage,
                "status": item.status,
                "duration_seconds": item.duration_seconds,
                "message": item.message,
            }
            for item in result.stage_statuses
        ]
    )
    _render_counts(result.summary)
    console.print(f"[green]Summary:[/green] {result.summary_path}")

    return run_id, result, report_path


def _render_doctor_table(checks: list[Any]) -> None:
    table = Table(title="WRX Doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Required")
    table.add_column("Details")
    table.add_column("How To Fix")

    for item in checks:
        status = "[green]PASS[/green]" if item.ok else "[red]FAIL[/red]"
        required = "yes" if item.required else "optional"
        fix = "-" if item.ok else item.fix
        table.add_row(item.name, status, required, item.details, fix)

    console.print(table)


def _is_local_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _apply_local_demo_overrides(
    run_config: dict[str, Any],
    include_scan: bool,
) -> dict[str, Any]:
    updated = dict(run_config)
    updated["seed_hosts"] = [JUICE_SHOP_URL]

    stages = dict(updated.get("stages", {}))
    stages["subdomains"] = False
    stages["zap_baseline"] = True
    stages["scan"] = include_scan
    updated["stages"] = stages

    tool_args = dict(updated.get("tool_args", {}))
    tool_args["probe"] = ["-silent", "-json", "-no-color"]
    tool_args["crawl"] = ["-silent", "-jsonl", "-depth", "2", "-concurrency", "5", "-timeout", "8"]
    if include_scan:
        # Keep nuclei in local mode focused and bounded.
        tool_args["scan"] = ["-silent", "-jsonl", "-rate-limit", "12", "-timeout", "8", "-tags", "misconfig"]
    updated["tool_args"] = tool_args

    timeouts = dict(updated.get("timeouts", {}))
    timeouts["probe"] = 120
    timeouts["crawl"] = 120
    if include_scan:
        timeouts["scan"] = 600
    timeouts["zap_baseline"] = 900
    updated["timeouts"] = timeouts

    updated["zap"] = {
        "docker_image": "owasp/zap2docker-stable",
        "baseline_args": ["-m", "3"],
        "timeout_seconds": 900,
        "localhost_only": True,
    }
    # Keep local-demo scans bounded and reproducible.
    updated["scan_hosts_only"] = True
    return updated


@app.command("init")
def init_command(target: str = typer.Argument(..., help="Target hostname or domain")) -> None:
    """Initialize a workspace and default wrx.yaml for a target."""
    _print_banner()
    root = init_workspace(Path.cwd(), target)
    console.print(f"[green]Workspace ready:[/green] {root}")
    console.print(f"[green]Config created:[/green] {root / 'wrx.yaml'}")


@app.command("run")
def run_command(
    target: str = typer.Argument(..., help="Target hostname or domain"),
    preset: str = typer.Option("quick", "--preset", "-p", help="Preset name from wrx.yaml"),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", "-c", help="Max concurrent jobs"),
    force: bool = typer.Option(False, "--force", help="Force stage re-execution even if cached"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands only, do not execute"),
    local_demo: bool = typer.Option(
        False,
        "--local-demo",
        help="Apply localhost Juice Shop overrides (seed host + passive ZAP).",
    ),
    with_scan: bool = typer.Option(
        False,
        "--with-scan",
        help="When used with --local-demo, keep nuclei scan enabled.",
    ),
    scan_profile: Optional[str] = typer.Option(
        None,
        "--scan-profile",
        help="Override scan profile (safe|balanced|deep) for nuclei/zap behavior.",
    ),
    triage: bool = typer.Option(
        False,
        "--triage",
        help="Enable finding triage clustering in summary output.",
    ),
    ollama: bool = typer.Option(
        False,
        "--ollama",
        help="Enable Ollama-assisted triage summarization (implies --triage).",
    ),
    ollama_model: str = typer.Option(
        "qwen2.5:7b",
        "--ollama-model",
        help="Ollama model to use when --ollama is enabled.",
    ),
    ollama_url: str = typer.Option(
        "http://127.0.0.1:11434",
        "--ollama-url",
        help="Ollama base URL when --ollama is enabled.",
    ),
) -> None:
    """Run recon pipeline for target using a preset."""
    _print_banner()

    workspace = ensure_workspace(Path.cwd(), target)
    config = load_config(workspace / "wrx.yaml")
    try:
        run_config = resolve_run_config(
            config,
            preset=preset,
            cli_concurrency=concurrency,
            scan_profile_override=scan_profile,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if triage or ollama:
        triage_cfg = dict(run_config.get("triage", {}))
        triage_cfg["enabled"] = True
        ollama_cfg = dict(triage_cfg.get("ollama", {}))
        if ollama:
            ollama_cfg["enabled"] = True
        ollama_cfg["model"] = ollama_model
        ollama_cfg["base_url"] = ollama_url
        triage_cfg["ollama"] = ollama_cfg
        run_config["triage"] = triage_cfg

    if local_demo:
        juice_check = check_juice_shop_reachable()
        if not juice_check.ok:
            console.print(f"[red]Juice Shop is not reachable at {JUICE_SHOP_URL}.[/red]")
            console.print("Start it with:")
            console.print(f"  {JUICE_SHOP_DOCKER_CMD}")
            raise typer.Exit(code=1)
        run_config = _apply_local_demo_overrides(run_config, include_scan=with_scan)
        console.print("[cyan]Local demo overrides applied (localhost + passive ZAP).[/cyan]")

    _run_with_resolved_config(
        workspace=workspace,
        pipeline_target=target,
        run_config=run_config,
        force=force,
        dry_run=dry_run,
    )


@app.command("doctor")
def doctor_command(
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Return non-zero exit code when required checks fail.",
    )
) -> None:
    """Run preflight checks for WRX and local Juice Shop demo readiness."""
    _print_banner()
    checks = run_doctor_checks(Path.cwd())
    _render_doctor_table(checks)

    required_failures = strict_failures(checks)
    optional_failures = sum(1 for item in checks if (not item.required and not item.ok))

    if required_failures == 0:
        console.print("[green]Doctor status:[/green] all required checks passed")
    else:
        console.print(f"[red]Doctor status:[/red] {required_failures} required check(s) failed")

    if optional_failures > 0:
        console.print(f"[yellow]Note:[/yellow] {optional_failures} optional check(s) failed")

    if strict and required_failures > 0:
        raise typer.Exit(code=1)


@app.command("demo")
def demo_command(
    demo_name_arg: str = typer.Argument(
        "juice-shop",
        help="Demo profile name. Use 'juice-shop' for localhost demo.",
    ),
    target: Optional[str] = typer.Option(
        None,
        "--target",
        help="Demo profile name (equivalent to positional argument).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands only, do not execute"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not auto-open report.html on macOS"),
    keep_running: bool = typer.Option(
        False,
        "--keep-running",
        help="Compatibility flag; WRX does not stop containers by default.",
    ),
) -> None:
    """Run safe localhost Juice Shop demo end-to-end."""
    _print_banner()

    demo_name = (target or demo_name_arg).strip()
    if demo_name != "juice-shop":
        console.print("[red]Demo safety check failed:[/red] only 'juice-shop' is supported.")
        console.print("Run: wrx demo juice-shop")
        raise typer.Exit(code=1)

    juice_check = check_juice_shop_reachable()
    if not juice_check.ok:
        console.print(f"[red]Juice Shop is not reachable at {JUICE_SHOP_URL}.[/red]")
        console.print("Start it with:")
        console.print(f"  {JUICE_SHOP_DOCKER_CMD}")
        raise typer.Exit(code=1)

    workspace = init_workspace(Path.cwd(), demo_name)
    console.print(f"[green]Demo workspace:[/green] {workspace}")

    config = load_config(workspace / "wrx.yaml")
    try:
        run_config = resolve_run_config(config, preset="demo", cli_concurrency=None)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    # Safety rail for demo mode: force localhost-only seed host and conservative stages.
    if not _is_local_url(JUICE_SHOP_URL):
        console.print("[red]Demo safety check failed:[/red] demo target must be localhost.")
        raise typer.Exit(code=1)

    run_config = _apply_local_demo_overrides(run_config, include_scan=False)
    run_config.setdefault("stages", {})["fuzz"] = False

    console.print("[cyan]ZAP baseline enabled (passive scan).[/cyan]")

    _, _, report_path = _run_with_resolved_config(
        workspace=workspace,
        pipeline_target=demo_name,
        run_config=run_config,
        force=True,
        dry_run=dry_run,
    )

    if keep_running:
        console.print("[cyan]--keep-running acknowledged:[/cyan] WRX does not stop containers by default.")

    if report_path and not no_open:
        if dry_run:
            console.print(f"[cyan][dry-run][/cyan] open {report_path}")
        else:
            subprocess.run(["open", str(report_path)], check=False)


@app.command("flow")
def flow_command(
    target: str = typer.Argument("juice-shop", help="Workspace target for preset flow."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print commands only, do not execute"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not auto-open final report"),
    with_scan: bool = typer.Option(
        False,
        "--with-scan",
        help="Enable nuclei stage during local flow for quick/bounty/deep presets.",
    ),
) -> None:
    """Run demo, quick, bounty, and deep presets sequentially for local Juice Shop."""
    _print_banner()
    juice_check = check_juice_shop_reachable()
    if not juice_check.ok:
        console.print(f"[red]Juice Shop is not reachable at {JUICE_SHOP_URL}.[/red]")
        console.print("Start it with:")
        console.print(f"  {JUICE_SHOP_DOCKER_CMD}")
        raise typer.Exit(code=1)

    workspace = init_workspace(Path.cwd(), target)
    config = load_config(workspace / "wrx.yaml")
    presets = ["demo", "quick", "bounty", "deep"]
    results_table = Table(title=f"WRX Preset Flow ({target})")
    results_table.add_column("Preset")
    results_table.add_column("Run ID")
    results_table.add_column("Alive Hosts", justify="right")
    results_table.add_column("URLs", justify="right")
    results_table.add_column("Nuclei", justify="right")
    results_table.add_column("ZAP", justify="right")

    last_report: Optional[Path] = None
    for preset in presets:
        console.print(f"[bold blue]Running preset:[/bold blue] {preset}")
        try:
            run_config = resolve_run_config(config, preset=preset, cli_concurrency=None)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

        include_scan = with_scan and preset != "demo"
        run_config = _apply_local_demo_overrides(run_config, include_scan=include_scan)
        if preset == "demo":
            run_config.setdefault("stages", {})["fuzz"] = False

        run_id, result, report_path = _run_with_resolved_config(
            workspace=workspace,
            pipeline_target=target,
            run_config=run_config,
            force=True,
            dry_run=dry_run,
        )
        last_report = report_path or last_report
        counts = result.summary.get("counts", {})
        results_table.add_row(
            preset,
            run_id,
            str(counts.get("alive_hosts", 0)),
            str(counts.get("urls", 0)),
            str(counts.get("nuclei_findings", 0)),
            str(counts.get("zap_findings", 0)),
        )

    console.print(results_table)
    if last_report and not no_open:
        if dry_run:
            console.print(f"[cyan][dry-run][/cyan] open {last_report}")
        else:
            subprocess.run(["open", str(last_report)], check=False)


@app.command("gui")
def gui_command(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host for dashboard server"),
    port: int = typer.Option(8787, "--port", help="Bind port for dashboard server"),
    target: Optional[str] = typer.Option(None, "--target", help="Preselect target workspace in GUI"),
    no_open: bool = typer.Option(False, "--no-open", help="Do not auto-open browser"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print server command and exit"),
) -> None:
    """Launch interactive WRX dashboard GUI for runs, findings, and diffs."""
    _print_banner()

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - runtime dependency guard
        console.print("[red]Missing GUI dependency:[/red] uvicorn not installed")
        console.print("Install with: pip install -e .")
        raise typer.Exit(code=1) from exc

    try:
        from wrx.gui import create_app, list_targets
    except ImportError as exc:  # pragma: no cover - defensive fallback
        console.print(f"[red]Failed to load GUI module:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    targets = list_targets(Path.cwd())
    target_ids = {item["id"] for item in targets}

    selected_target = target
    if selected_target and selected_target not in target_ids:
        fallback = selected_target
        selected_target = None
        for item in targets:
            if item.get("display_name") == fallback:
                selected_target = item["id"]
                break
        if selected_target is None:
            console.print(f"[red]Target workspace not found for GUI:[/red] {fallback}")
            raise typer.Exit(code=1)

    url = f"http://{host}:{port}"
    console.print(f"[green]Launching WRX GUI:[/green] {url}")
    if selected_target:
        console.print(f"[cyan]Preselected target:[/cyan] {selected_target}")

    if dry_run:
        console.print(f"[cyan][dry-run][/cyan] uvicorn wrx.gui:create_app --host {host} --port {port}")
        return

    if not no_open:
        webbrowser.open(url)

    app_obj = create_app(base_dir=Path.cwd(), default_target=selected_target)
    uvicorn.run(app_obj, host=host, port=port, log_level="info")


@app.command("diff")
def diff_command(
    target: str = typer.Argument(..., help="Target hostname or domain"),
    last: int = typer.Option(1, "--last", help="Compare against Nth previous completed run"),
) -> None:
    """Diff latest run against previous run(s)."""
    _print_banner()
    workspace = ensure_workspace(Path.cwd(), target)
    try:
        payload = compute_workspace_diff(workspace, last=last)
    except ValueError as exc:
        console.print(f"[red]Diff failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    changes = payload["changes"]

    table = Table(title=f"WRX Diff ({payload['meta']['previous_run']} -> {payload['meta']['current_run']})")
    table.add_column("Category")
    table.add_column("New", justify="right")
    table.add_column("Removed", justify="right")

    for key in ["subdomains", "alive_hosts", "urls", "nuclei_findings", "zap_findings"]:
        table.add_row(key, str(len(changes[key]["new"])), str(len(changes[key]["removed"])))
    console.print(table)

    console.print(f"[green]Diff JSON:[/green] {workspace / 'data' / 'diff.json'}")


@app.command("report")
def report_command(target: str = typer.Argument(..., help="Target hostname or domain")) -> None:
    """Regenerate report.html from normalized JSON data."""
    _print_banner()
    workspace = ensure_workspace(Path.cwd(), target)
    try:
        report_path = generate_report(workspace)
    except ValueError as exc:
        console.print(f"[red]Report failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Report generated:[/green] {report_path}")


@app.command("export")
def export_command(
    target: str = typer.Argument(..., help="Target hostname or domain"),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Export format: markdown, sarif, github, jira",
    ),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Specific run id. Defaults to latest run."),
    out: Optional[Path] = typer.Option(None, "--out", help="Output file path. Defaults under runs/<run_id>/exports."),
    jira_project: str = typer.Option("SEC", "--jira-project", help="Jira project key for jira export payload."),
    jira_issue_type: str = typer.Option("Task", "--jira-issue-type", help="Jira issue type name."),
) -> None:
    """Export normalized findings to Markdown, SARIF, GitHub, or Jira payloads."""
    _print_banner()
    workspace = ensure_workspace(Path.cwd(), target)
    resolved_run_id = run_id
    if not resolved_run_id:
        resolved_run_id = current_run_id(workspace)
    if not resolved_run_id:
        completed = list_completed_runs(workspace)
        resolved_run_id = completed[-1] if completed else None
    if not resolved_run_id:
        console.print("[red]Export failed:[/red] no completed runs found.")
        raise typer.Exit(code=1)

    summary_path = workspace / "runs" / resolved_run_id / "data" / "summary.json"
    summary = read_json(summary_path, default={})
    if not summary and not run_id:
        # Current marker can point to an incomplete run; fall back to latest completed summary.
        for candidate in reversed(list_completed_runs(workspace)):
            candidate_path = workspace / "runs" / candidate / "data" / "summary.json"
            candidate_summary = read_json(candidate_path, default={})
            if candidate_summary:
                resolved_run_id = candidate
                summary_path = candidate_path
                summary = candidate_summary
                break
    if not summary:
        console.print(f"[red]Export failed:[/red] summary not found for run {resolved_run_id}")
        raise typer.Exit(code=1)

    try:
        ext, content = render_export_payload(
            fmt,
            summary=summary,
            target=target,
            run_id=resolved_run_id,
            jira_project=jira_project,
            jira_issue_type=jira_issue_type,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if out is None:
        out = workspace / "runs" / resolved_run_id / "exports" / f"{fmt.lower()}.{ext}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    console.print(f"[green]Export generated:[/green] {out}")


if __name__ == "__main__":
    app()
