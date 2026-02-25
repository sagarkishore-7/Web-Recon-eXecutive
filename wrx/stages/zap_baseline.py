"""OWASP ZAP baseline stage using Docker (passive scan only)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import urlparse, urlunparse

from wrx.models import ZapFinding
from wrx.normalize.zap import parse_zap_json
from wrx.workspace import write_json

RunCommand = Callable[[list[str], Path, int], Awaitable[int]]

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_FALLBACK_IMAGES = ["zaproxy/zap-stable"]


def _is_local_target(target_url: str) -> bool:
    parsed = urlparse(target_url)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname.lower() in _LOCAL_HOSTS

    lowered = target_url.strip().lower()
    return lowered in _LOCAL_HOSTS or lowered.startswith("localhost:") or lowered.startswith("127.0.0.1:")


def _docker_reachable_target(target_url: str) -> str:
    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.hostname:
        return target_url

    hostname = parsed.hostname.lower()
    if hostname not in _LOCAL_HOSTS:
        return target_url

    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        host_port = hostport
        prefix = f"{userinfo}@"
    else:
        host_port = netloc
        prefix = ""

    if ":" in host_port:
        _, _, port = host_port.partition(":")
        replaced = f"host.docker.internal:{port}" if port else "host.docker.internal"
    else:
        replaced = "host.docker.internal"

    return urlunparse(parsed._replace(netloc=f"{prefix}{replaced}"))


def _serialize_findings(findings: list[ZapFinding]) -> list[dict]:
    return [
        {
            "plugin_id": item.plugin_id,
            "alert": item.alert,
            "risk": item.risk,
            "confidence": item.confidence,
            "url": item.url,
            "evidence": item.evidence,
            "description": item.description,
            "solution": item.solution,
            "reference": item.reference,
            "cweid": item.cweid,
            "wascid": item.wascid,
            "instances": item.instances,
            "hash": item.hash,
        }
        for item in findings
    ]


def _sanitize_baseline_args(args: list[str]) -> list[str]:
    skip_next = False
    cleaned: list[str] = []
    for idx, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue

        if arg in {"-J", "-r", "-x", "-w", "--jsonreport", "--report", "--xmlreport", "--mdreport"}:
            if idx + 1 < len(args):
                skip_next = True
            continue

        cleaned.append(arg)

    return cleaned


async def execute(
    target_url: str,
    raw_root: Path,
    data_root: Path,
    run_cmd: RunCommand,
    docker_image: str,
    baseline_args: list[str],
    timeout: int,
    localhost_only: bool,
) -> dict:
    stage = "zap_baseline"
    stage_dir = raw_root / stage
    stage_dir.mkdir(parents=True, exist_ok=True)

    log_path = stage_dir / "logs.txt"
    zap_json_path = stage_dir / "zap.json"
    data_path = data_root / f"{stage}.json"

    artifacts = {
        "zap_json": f"raw/{stage}/zap.json",
        "zap_html": f"raw/{stage}/zap.html",
    }

    if not target_url.strip():
        log_path.write_text("[wrx] no zap target available; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "No target URL available for ZAP baseline",
            "zap_findings": [],
            "artifacts": artifacts,
        }
        write_json(data_path, payload)
        return payload

    if localhost_only and not _is_local_target(target_url):
        log_path.write_text("[wrx] refused non-local target for ZAP demo stage.\n", encoding="utf-8")
        payload = {
            "status": "error",
            "reason": f"ZAP baseline is restricted to localhost targets in this preset: {target_url}",
            "zap_findings": [],
            "artifacts": artifacts,
        }
        write_json(data_path, payload)
        return payload

    if shutil.which("docker") is None:
        log_path.write_text("[wrx] docker not found in PATH; stage skipped.\n", encoding="utf-8")
        payload = {
            "status": "skipped",
            "reason": "docker not found in PATH",
            "zap_findings": [],
            "artifacts": artifacts,
        }
        write_json(data_path, payload)
        return payload

    docker_target = _docker_reachable_target(target_url)
    base_args = _sanitize_baseline_args(list(baseline_args))
    candidate_images = [docker_image] + [img for img in _FALLBACK_IMAGES if img != docker_image]
    selected_image = docker_image
    exit_code = 125
    success_codes = {0, 1, 2}

    for index, image in enumerate(candidate_images):
        selected_image = image
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{stage_dir}:/zap/wrk:rw",
            image,
            "zap-baseline.py",
            "-t",
            docker_target,
            "-J",
            "zap.json",
            "-r",
            "zap.html",
        ] + base_args
        exit_code = await run_cmd(cmd, log_path, timeout)
        if exit_code in success_codes:
            break
        if exit_code != 125 or index == len(candidate_images) - 1:
            break

    findings = parse_zap_json(zap_json_path)
    payload = {
        "status": "completed" if exit_code in success_codes else "error",
        "exit_code": exit_code,
        "docker_image": selected_image,
        "target_url": target_url,
        "docker_target_url": docker_target,
        "zap_findings": _serialize_findings(findings),
        "artifacts": artifacts,
    }
    write_json(data_path, payload)
    return payload
