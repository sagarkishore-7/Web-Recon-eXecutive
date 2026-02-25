"""Data models and serialization helpers for WRX."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha1
from typing import Any, Optional


def now_utc_iso() -> str:
    """Return an ISO-8601 timestamp in UTC without microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(*parts: Any) -> str:
    """Generate a deterministic SHA1 hash from key fields."""
    joined = "|".join(str(part).strip() for part in parts)
    return sha1(joined.encode("utf-8")).hexdigest()


@dataclass
class TargetMetadata:
    target: str
    timestamp: str
    preset: str
    run_id: str
    tool_versions: dict[str, str] = field(default_factory=dict)
    artifact_paths: dict[str, str] = field(default_factory=dict)


@dataclass
class AliveHost:
    url: str
    status_code: int
    title: Optional[str] = None
    tech: list[str] = field(default_factory=list)
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = stable_hash(self.url, self.status_code)


@dataclass
class DiscoveredURL:
    url: str
    source_stage: str
    discovered_at: str
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = stable_hash(self.url)


@dataclass
class NucleiFinding:
    template_id: str
    severity: str
    name: str
    matched_at: str
    extracted_results: list[str] = field(default_factory=list)
    timestamp: str = ""
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = now_utc_iso()
        if not self.hash:
            self.hash = stable_hash(self.template_id, self.matched_at)


@dataclass
class ZapFinding:
    plugin_id: str
    alert: str
    risk: str
    confidence: str
    url: str = ""
    evidence: str = ""
    description: str = ""
    solution: str = ""
    reference: str = ""
    cweid: str = ""
    wascid: str = ""
    instances: int = 0
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.hash:
            self.hash = stable_hash(
                self.plugin_id,
                self.alert,
                self.risk,
                self.url,
            )


@dataclass
class Summary:
    metadata: TargetMetadata
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[AliveHost] = field(default_factory=list)
    urls: list[DiscoveredURL] = field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = field(default_factory=list)
    zap_findings: list[ZapFinding] = field(default_factory=list)
    triage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["counts"] = {
            "subdomains": len(self.subdomains),
            "alive_hosts": len(self.alive_hosts),
            "urls": len(self.urls),
            "nuclei_findings": len(self.nuclei_findings),
            "zap_findings": len(self.zap_findings),
        }
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Summary":
        meta = TargetMetadata(**payload["metadata"])
        alive_hosts = [AliveHost(**item) for item in payload.get("alive_hosts", [])]
        urls = [DiscoveredURL(**item) for item in payload.get("urls", [])]
        findings = [NucleiFinding(**item) for item in payload.get("nuclei_findings", [])]
        zap_findings = [ZapFinding(**item) for item in payload.get("zap_findings", [])]
        return cls(
            metadata=meta,
            subdomains=payload.get("subdomains", []),
            alive_hosts=alive_hosts,
            urls=urls,
            nuclei_findings=findings,
            zap_findings=zap_findings,
            triage=payload.get("triage", {}),
        )
