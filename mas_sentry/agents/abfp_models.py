"""
ABFP — Agent Behavioral Fingerprinting Protocol
Core data models: MessageEvent, AgentFingerprint, BehavioralBaseline
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import json


@dataclass
class MessageEvent:
    """Single captured message event from an agent"""
    topic: str
    payload_size: int
    timestamp: float
    qos: int = 0
    retain: bool = False
    payload_preview: str = ""

    def to_dict(self) -> Dict:
        return {
            "topic": self.topic,
            "payload_size": self.payload_size,
            "timestamp": self.timestamp,
            "qos": self.qos,
            "retain": self.retain,
        }


@dataclass
class TopicProfile:
    """Profile of a single topic used by an agent"""
    topic: str
    message_count: int = 0
    total_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    qos_levels: List[int] = field(default_factory=list)
    retain_count: int = 0

    @property
    def avg_payload_bytes(self) -> float:
        return self.total_bytes / self.message_count if self.message_count else 0

    @property
    def retain_ratio(self) -> float:
        return self.retain_count / self.message_count if self.message_count else 0


@dataclass
class TimingMetrics:
    """Timing cadence metrics for an agent"""
    mean_interval_ms: float = 0.0
    std_interval_ms: float = 0.0
    min_interval_ms: float = 0.0
    max_interval_ms: float = 0.0
    burst_detected: bool = False
    burst_threshold_ms: float = 50.0
    sample_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "mean_interval_ms": round(self.mean_interval_ms, 2),
            "std_interval_ms": round(self.std_interval_ms, 2),
            "min_interval_ms": round(self.min_interval_ms, 2),
            "max_interval_ms": round(self.max_interval_ms, 2),
            "burst_detected": self.burst_detected,
            "sample_count": self.sample_count,
        }


@dataclass
class PayloadMetrics:
    """Payload signature metrics for an agent"""
    mean_size_bytes: float = 0.0
    std_size_bytes: float = 0.0
    min_size_bytes: int = 0
    max_size_bytes: int = 0
    entropy_score: float = 0.0
    encoding: str = "unknown"   # json / binary / plaintext / base64

    def to_dict(self) -> Dict:
        return {
            "mean_size_bytes": round(self.mean_size_bytes, 2),
            "std_size_bytes": round(self.std_size_bytes, 2),
            "min_size_bytes": self.min_size_bytes,
            "max_size_bytes": self.max_size_bytes,
            "entropy_score": round(self.entropy_score, 3),
            "encoding": self.encoding,
        }
