import click
from rich.console import Console
from mas_sentry.core.engine import SentryEngine
from mas_sentry.core.config import SentryConfig

console = Console()

@click.group()
@click.version_option("0.1.0")
def cli():
    """MAS-Sentry-Toolkit — Multi-Agent System Security Auditor"""
    pass

@cli.command()
@click.option("--broker", default="127.0.0.1", help="Broker IP")
@click.option("--port", default=1883, help="Broker port")
@click.option("--topic", default="#", help="Topic filter")
@click.option("--duration", default=60, help="Duration in seconds")
def sniff(broker, port, topic, duration):
    """Passive MQTT traffic sniffer"""
    console.print(f"[bold yellow]Starting MQTT sniff on {broker}:{port} topic={topic}[/bold yellow]")

@cli.command()
@click.option("--broker", default="127.0.0.1")
@click.option("--duration", default=120)
@click.option("--output", default="report.json")
def abfp(broker, duration, output):
    """Run ABFP behavioral fingerprinting"""
    console.print(f"[bold cyan]Running ABFP on {broker} for {duration}s[/bold cyan]")

@cli.command()
@click.option("--target", required=True)
@click.option("--protocol", default="mqtt")
@click.option("--full", is_flag=True)
def audit(target, protocol, full):
    """Run full security audit"""
    engine = SentryEngine()
    engine.start_session(target, protocol)

if __name__ == "__main__":
    cli()
