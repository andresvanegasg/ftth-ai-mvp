#!/usr/bin/env bash
set -e

HOST="127.0.0.1"
PORT="5140"

echo "=== DEMO CONTROLADA FTTH AI ==="
echo "1) Trafico normal (30 eventos)"
for i in $(seq 1 30); do
  echo "<13>security: severity=info event=DemoNormal msg=\"normal $i\" " | nc -u -w1 "$HOST" "$PORT"
  sleep 0.15
done

echo "2) Pausa 5s (para observar en dashboard)"
sleep 5

echo "3) Burst de errores (80 eventos) - debe disparar AI_ALERT"
for i in $(seq 1 80); do
  echo "<13>security: severity=error event=DemoBurst msg=\"burst $i\" " | nc -u -w1 "$HOST" "$PORT"
done

echo "4) Fin. Espera 60s para que el AI detector procese (si tu POLL=60)"
echo "   Revisa Grafana: AI Alerts, Live log, tabla Latest AI Alerts"
