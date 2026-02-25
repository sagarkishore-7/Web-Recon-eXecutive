"""Vulnerability scan stage using nuclei."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Awaitable, Callable

from wrx.models import NucleiFinding
from wrx.normalize.nuclei import parse_nuclei_jsonl
from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]


def _serialize_findings(findings: list[NucleiFinding]) -> list[dict]:
    return [
        {
            "template_id": item.template_id,
            "severity": item.severity,
            "name": item.name,
            "matched_at": item.matched_at,
            "extracted_results": item.extracted_results,
            "timestamp": item.timestamp,
            "hash": item.hash,
        }
        for item in findings
    ]


def _tool_supports_flag(tool: str, flag: str) -> bool:
    for help_flag in ("-h", "--help"):
        try:
            result = subprocess.run(
                [tool, help_flag],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue

        output = f"{result.stdout}\n{result.stderr}"
        if flag in output:
            return True
    return False


def _normalize_output_flags(args: list[str]) -> list[str]:
    normalized = [item for item in args if item not in {"-jsonl", "-json"}]
    if _tool_supports_flag("nuclei", "-jsonl"):
        normalized.append("-jsonl")
    elif _tool_supports_flag("nuclei", "-json"):
        normalized.append("-json")
    return normalized


async def execute(
    targets: list[str],
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    args: list[str],
    timeout: int,
) -> dict:
    stage = "scan"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    targets_path = stage_dir / "targets.txt"
    output_path = stage_dir / "nuclei.jsonl"
    data_path = data_root / f"{stage}.json"

    unique_targets = sorted({item.strip() for item in targets if item.strip()})
    if not unique_targets:
        log_path.write_text("[wrx] no scan targets available; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "No targets available for nuclei",
            "nuclei_findings": [],
        }
        write_json(data_path, payload)
        return payload

    targets_path.write_text("\n".join(unique_targets) + "\n", encoding="utf-8")

    if shutil.which("nuclei") is None:
        log_path.write_text("[wrx] nuclei not found in PATH; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "nuclei not found in PATH",
            "nuclei_findings": [],
        }
        write_json(data_path, payload)
        return payload

    cmd_args = _normalize_output_flags(list(args))
    cmd = ["nuclei", "-l", str(targets_path), "-o", str(output_path)] + cmd_args
    exit_code = await run_cmd(cmd, log_path, timeout)

    findings = parse_nuclei_jsonl(output_path)
    payload = {
        "status": "completed" if exit_code == 0 else "error",
        "exit_code": exit_code,
        "nuclei_findings": _serialize_findings(findings),
    }
    write_json(data_path, payload)
    return payload
