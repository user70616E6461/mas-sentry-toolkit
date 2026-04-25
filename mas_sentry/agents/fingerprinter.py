"""
ABFPFingerprinter — Phase 1 & 2 implementation.
Passive collection + fingerprint construction.
"""
import paho.mqtt.client as mqtt
import time
import math
from typing import Dict, List, Optional
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .abfp_models import (
    AgentFingerprint, MessageEvent,
    TopicProfile, TimingMetrics, PayloadMetrics
)
from .payload_analyzer import shannon_entropy, detect_encoding, scan_sensitive

console = Console()


class ABFPFingerprinter:
    """
    ABFP Phase 1: Passive behavioral data collection.
    ABFP Phase 2: Fingerprint construction from collected data.

    Infers agent identity from topic naming patterns:
      sensors/sensor_001/telemetry → agent_id: inferred_sensors_sensor_001
    """

    MIN_MESSAGES_FOR_CONFIDENCE = 10

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.fingerprints: Dict[str, AgentFingerprint] = {}
        self._total_messages = 0

    def _infer_agent_id(self, topic: str) -> str:
        parts = topic.split("/")
        if len(parts) >= 2:
            return f"inferred_{parts[0]}_{parts[1]}"
        return f"inferred_{parts[0]}"

    def _get_or_create(self, agent_id: str, now: float) -> AgentFingerprint:
        if agent_id not in self.fingerprints:
            self.fingerprints[agent_id] = AgentFingerprint(
                agent_id=agent_id,
                first_seen=now,
                last_seen=now
            )
            console.print(f"[cyan][ABFP] New agent discovered: {agent_id}[/cyan]")
        return self.fingerprints[agent_id]

    def collect(self, duration: int = 60,
                topic_filter: str = "#") -> Dict[str, AgentFingerprint]:
        """Phase 1: Passive collection"""
        client = mqtt.Client(client_id="mas-sentry-abfp")

        def on_message(c, u, msg):
            now = time.time()
            agent_id = self._infer_agent_id(msg.topic)
            fp = self._get_or_create(agent_id, now)
            fp.last_seen = now

            # Update topic profile
            if msg.topic not in fp.topic_profiles:
                fp.topic_profiles[msg.topic] = TopicProfile(
                    topic=msg.topic, first_seen=now
                )
            tp = fp.topic_profiles[msg.topic]
            tp.message_count += 1
            tp.total_bytes += len(msg.payload)
            tp.last_seen = now
            tp.qos_levels.append(msg.qos)
            if msg.retain:
                tp.retain_count += 1

            # Store event
            preview = msg.payload.decode("utf-8", errors="replace")[:40]
            fp.message_events.append(MessageEvent(
                topic=msg.topic,
                payload_size=len(msg.payload),
                timestamp=now,
                qos=msg.qos,
                retain=bool(msg.retain),
                payload_preview=preview
            ))
            self._total_messages += 1

        def on_connect(c, u, f, rc):
            if rc == 0:
                c.subscribe(topic_filter, qos=0)
                console.print(
                    f"[bold green][ABFP] Phase 1 started — "
                    f"collecting for {duration}s on '{topic_filter}'[/bold green]"
                )

        client.on_message = on_message
        client.on_connect = on_connect
        client.connect(self.host, self.port)
        client.loop_start()

        start = time.time()
        while time.time() - start < duration:
            elapsed = int(time.time() - start)
            agents = len(self.fingerprints)
            msgs = self._total_messages
            print(
                f"\r[ABFP] {elapsed}s | {agents} agents | {msgs} messages    ",
                end=""
            )
            time.sleep(1)

        client.loop_stop()
        client.disconnect()
        print()
        console.print(
            f"[bold green][ABFP] Phase 1 complete: "
            f"{len(self.fingerprints)} agents, "
            f"{self._total_messages} messages[/bold green]"
        )
        return self.fingerprints
