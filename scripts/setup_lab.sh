#!/bin/bash
set -e

echo "[*] MAS-Sentry Lab Setup"
echo "========================"

echo "[*] Checking Docker..."
docker --version || { echo "[-] Docker not found. Install Docker first."; exit 1; }
docker-compose --version || docker compose version || { echo "[-] docker-compose not found."; exit 1; }

echo "[*] Building Docker images..."
docker-compose build

echo "[*] Starting lab..."
docker-compose up -d

echo "[*] Waiting for services..."
sleep 4

echo ""
echo "[*] Lab status:"
docker-compose ps

echo ""
echo "[+] Lab ready!"
echo "    MQTT Broker : 127.0.0.1:1883  (anonymous access ON)"
echo "    WebSockets  : 127.0.0.1:9001"
echo "    RabbitMQ    : 127.0.0.1:5672"
echo "    RabbitMQ UI : http://127.0.0.1:15672  (guest/guest)"
echo ""
echo "[*] Quick test:"
echo "    mosquitto_sub -h 127.0.0.1 -t '#' -v"
echo ""
echo "[*] Start sniffer:"
echo "    python3 -m mas_sentry sniff --broker 127.0.0.1"
