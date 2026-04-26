"""
ABFP Phase 3 — Anomaly Detection Engine.
Detects behavioral deviations, rogue agents, privilege escalation.
"""
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .abfp_models import AgentFingerprint, BehavioralBaseline

console = Console()


@dataclass
class AnomalyFinding:
    """Single anomaly finding from the detector"""
    agent_id: str
    finding_type: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    score_contribution: float
    description: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "score_contribution": round(self.score_contribution, 2),
            "description": self.description,
            "evidence": self.evidence,
        }


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


class AnomalyDetector:
    """
    ABFP Phase 3: Behavioral anomaly detection.

    Detects:
    - Z-score timing deviation
    - New topic emergence (privilege escalation)
    - Payload size spikes
    - Entropy anomalies (encryption/obfuscation)
    - Burst attack patterns
    - Rogue agents (no matching baseline)
    """

    # Thresholds
    TIMING_ZSCORE_THRESHOLD   = 2.5
    PAYLOAD_SPIKE_RATIO       = 3.0
    ENTROPY_HIGH_THRESHOLD    = 7.0   # near-random = encrypted/compressed
    ENTROPY_LOW_THRESHOLD     = 0.5   # near-zero = suspicious repetition
    BURST_INTERVAL_MS         = 50.0

    def __init__(self, baselines: Optional[Dict[str, BehavioralBaseline]] = None):
        self.baselines = baselines or {}
        self.findings: List[AnomalyFinding] = []

    def _add(self, agent_id: str, finding_type: str, severity: str,
             score: float, description: str, evidence: dict = None):
        f = AnomalyFinding(
            agent_id=agent_id,
            finding_type=finding_type,
            severity=severity,
            score_contribution=score,
            description=description,
            evidence=evidence or {}
        )
        self.findings.append(f)
        color = SEVERITY_COLORS.get(severity, "white")
        console.print(f"[{color}][{severity}] {agent_id}: {description}[/{color}]")
        return f

    def analyze(self, fingerprints: Dict[str, AgentFingerprint]) -> Dict[str, AgentFingerprint]:
        """Run all anomaly checks on collected fingerprints"""
        self.findings.clear()
        console.print("[bold cyan][ABFP] Phase 3 — Running anomaly detection...[/bold cyan]")

        for agent_id, fp in fingerprints.items():
            score = 0.0
            fp.threat_flags.clear()

            score += self._check_timing(fp)
            score += self._check_payload_spike(fp)
            score += self._check_entropy(fp)
            score += self._check_burst(fp)
            score += self._check_new_topics(fp)
            score += self._check_rogue(fp)

            fp.anomaly_score = min(score, 100.0)
            fp.is_rogue = fp.anomaly_score >= 70.0

        return fingerprints
