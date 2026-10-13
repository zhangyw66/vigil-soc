"""Deterministic scoring: rules + threat-intelligence reputation.

This pass runs *without any LLM* — it is the explainable anchor of the hybrid
triage design. When it disagrees with the model by more than
``escalation_delta``, the event is escalated to a human instead of decided.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

from vigil.models.event import NormalizedEvent
from vigil.models.triage import EvidenceItem

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

_SUSPICIOUS_INTERPRETERS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "cscript.exe",
}
_BENIGN_PROCESSES = {
    "chrome.exe", "explorer.exe", "outlook.exe", "teams.exe", "svchost.exe",
    "winword.exe", "excel.exe",
}


@dataclass(frozen=True)
class ThreatIntel:
    """Reputation sets. The bundled file only ships EXAMPLE indicators."""

    malicious_hashes: frozenset[str] = frozenset()
    malicious_ips: frozenset[str] = frozenset()
    malicious_domains: frozenset[str] = frozenset()

    @classmethod
    def empty(cls) -> ThreatIntel:
        return cls()

    @classmethod
    def from_file(cls, path: Path | None) -> ThreatIntel:
        if path is None or not path.exists():
            return cls.empty()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls.empty()
        return cls(
            malicious_hashes=frozenset(str(h).lower() for h in data.get("malicious_hashes", [])),
            malicious_ips=frozenset(data.get("malicious_ips", [])),
            malicious_domains=frozenset(d.lower() for d in data.get("malicious_domains", [])),
        )


def extract_iocs(event: NormalizedEvent) -> list[str]:
    """Extract IPs / hashes / domains from event text fields (deduped)."""
    haystack = " ".join(
        part for part in (event.cmdline, event.file_path, event.file_hash, event.dst_ip) if part
    )
    found: list[str] = []
    found.extend(_IP_RE.findall(haystack))
    found.extend(_SHA256_RE.findall(haystack))
    found.extend(_MD5_RE.findall(haystack))
    found.extend(_DOMAIN_RE.findall(haystack))
    return sorted({v.lower() for v in found})


def is_private_ip(text: str | None) -> bool:
    if not text:
        return False
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


def _cap(value: float) -> float:
    return max(0.0, min(100.0, value))


class DeterministicScorer:
    """Rule + reputation scorer. Outputs a 0-100 score and evidence."""

    def __init__(self, ti: ThreatIntel | None = None) -> None:
        self.ti = ti or ThreatIntel.empty()

    def score(self, event: NormalizedEvent) -> tuple[float, list[EvidenceItem], list[str]]:
        points = 50.0
        reasons: list[EvidenceItem] = []
        cmd = (event.cmdline or "").lower()
        proc = (event.process or "").lower()

        # --- threat intelligence hits (highest weight) ---
        if event.file_hash and event.file_hash.lower() in self.ti.malicious_hashes:
            points += 40
            reasons.append(EvidenceItem(
                claim="file hash matches known-malicious indicator",
                source_ref="ti." + event.file_hash,
                kind="ti_lookup",
            ))
        for ip in (event.src_ip, event.dst_ip):
            if ip and ip in self.ti.malicious_ips:
                points += 40
                reasons.append(EvidenceItem(
                    claim=f"address {ip} matches known-malicious indicator",
                    source_ref=f"ti.{ip}",
                    kind="ti_lookup",
                ))
        for domain in _DOMAIN_RE.findall(cmd):
            if domain.lower() in self.ti.malicious_domains:
                points += 40
                reasons.append(EvidenceItem(
                    claim=f"domain {domain} in command line matches malicious indicator",
                    source_ref="ti." + domain,
                    kind="ti_lookup",
                ))

        # --- suspicious-command rules ---
        if "-enc" in cmd or "-encodedcommand" in cmd:
            points += 25
            reasons.append(EvidenceItem(
                claim="command line uses encoded PowerShell",
                source_ref="event.cmdline", kind="rule_hit"))
        if "frombase64string" in cmd:
            points += 20
            reasons.append(EvidenceItem(
                claim="command line decodes base64 content", source_ref="event.cmdline", kind="rule_hit"))
        if "schtasks /create" in cmd or "schtasks.exe /create" in cmd or "wmic process call create" in cmd:
            points += 25
            reasons.append(EvidenceItem(
                claim="persistence/execution via scheduled task or wmic",
                source_ref="event.cmdline", kind="rule_hit"))
        if "mimikatz" in cmd:
            points += 40
            reasons.append(EvidenceItem(
                claim="credential-dump tool (mimikatz) referenced in command line",
                source_ref="event.cmdline", kind="rule_hit"))
        if proc in _SUSPICIOUS_INTERPRETERS:
            points += 10
            reasons.append(EvidenceItem(
                claim=f"process is a script interpreter ({event.process})",
                source_ref="event.process", kind="rule_hit"))
        if event.event_type in {"user_added", "account_created", "privilege_assigned"}:
            points += 20
            reasons.append(EvidenceItem(
                claim="privilege/account change event", source_ref="event.event_type", kind="rule_hit"))
        sys_account = (event.user or "").lower() in {"system", "root", "administrator"}
        if sys_account and event.event_type == "network_connection":
            points += 10
            reasons.append(EvidenceItem(
                claim="system-level account performing a network action",
                source_ref="event.user", kind="rule_hit"))

        # --- mitigation signals (reduce suspicion) ---
        if is_private_ip(event.dst_ip) and not any(r.kind == "ti_lookup" for r in reasons):
            points -= 15
            reasons.append(EvidenceItem(
                claim="destination is a private (internal) address",
                source_ref="event.dst_ip", kind="event_field"))
        if is_private_ip(event.src_ip):
            points -= 5
            reasons.append(EvidenceItem(
                claim="source is a private (internal) address",
                source_ref="event.src_ip", kind="event_field"))
        if proc in _BENIGN_PROCESSES and not any(r.kind == "rule_hit" for r in reasons):
            points -= 15
            reasons.append(EvidenceItem(
                claim="process is a common benign application",
                source_ref="event.process", kind="event_field"))
        routine_event = event.event_type in {"user_logon", "file_access"}
        if routine_event and not any(r.kind == "rule_hit" for r in reasons):
            points -= 20
            reasons.append(EvidenceItem(
                claim="routine operational event type with no rule hits",
                source_ref="event.event_type", kind="event_field"))

        return _cap(points), reasons, extract_iocs(event)
