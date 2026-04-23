import socket
import time
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from .base import BaseProtocolAnalyzer, CapturedMessage
from datetime import datetime

console = Console()

class AMQPAnalyzer(BaseProtocolAnalyzer):
    """
    AMQP analyzer using RabbitMQ Management API (port 15672).
    Enumerates exchanges, queues, bindings, and connections
    without requiring a full AMQP client library.
    """

    def __init__(self, host: str, port: int = 5672,
                 username: str = "guest", password: str = "guest",
                 mgmt_port: int = 15672, vhost: str = "%2F"):
        super().__init__(host, port)
        self.username = username
        self.password = password
        self.mgmt_port = mgmt_port
        self.vhost = vhost
        self.exchanges: List[Dict] = []
        self.queues: List[Dict] = []
        self.bindings: List[Dict] = []
        self.connections: List[Dict] = []

    def _api_get(self, path: str) -> Optional[Any]:
        url = f"http://{self.host}:{self.mgmt_port}/api/{path}"
        req = urllib.request.Request(url)
        import base64
        creds = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        req.add_header("Authorization", f"Basic {creds}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            console.print(f"[red][AMQP] API error {e.code} on {path}[/red]")
            return None
        except Exception as e:
            console.print(f"[red][AMQP] Cannot reach management API: {e}[/red]")
            return None

    def connect(self) -> bool:
        data = self._api_get("overview")
        if data:
            console.print(f"[bold green][AMQP] Management API accessible at {self.host}:{self.mgmt_port}[/bold green]")
            console.print(f"[green][AMQP] RabbitMQ version: {data.get('rabbitmq_version','unknown')}[/green]")
            self.is_running = True
            return True
        return False

    def disconnect(self):
        self.is_running = False

    def capture(self, duration: int = 30) -> List[CapturedMessage]:
        console.print("[yellow][AMQP] Capture via management API — use enumerate_topics() for full audit[/yellow]")
        return self.messages

    def enumerate_topics(self) -> List[str]:
        return [q.get("name", "") for q in self.queues]


    def enumerate_exchanges(self) -> List[Dict]:
        data = self._api_get(f"exchanges/{self.vhost}")
        if not data:
            return []
        self.exchanges = data

        table = Table(title="[bold]AMQP Exchanges[/bold]")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Durable", style="green")
        table.add_column("Auto-delete", style="red")

        for ex in self.exchanges:
            name = ex.get("name") or "[default]"
            table.add_row(
                name,
                ex.get("type", "?"),
                str(ex.get("durable", False)),
                str(ex.get("auto_delete", False))
            )
        console.print(table)
        return self.exchanges

    def enumerate_queues(self) -> List[Dict]:
        data = self._api_get(f"queues/{self.vhost}")
        if not data:
            return []
        self.queues = data

        table = Table(title="[bold]AMQP Queues[/bold]")
        table.add_column("Name", style="cyan")
        table.add_column("Messages", style="yellow", justify="right")
        table.add_column("Consumers", style="green", justify="right")
        table.add_column("Durable", style="blue")

        for q in self.queues:
            table.add_row(
                q.get("name", "?"),
                str(q.get("messages", 0)),
                str(q.get("consumers", 0)),
                str(q.get("durable", False))
            )
        console.print(table)
        return self.queues
