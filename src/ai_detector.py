import time
import re
import socket
from datetime import datetime, timedelta, timezone
import requests

# =========================
# CONFIGURACIÓN (MVP)
# =========================
LOKI_URL = "http://localhost:3100"

# Labels que Promtail agrega (según tu config actual)
QUERY = '{job="syslog", source="syslogng"}'

# Ventana de análisis (minutos) y cada cuánto evalúa (segundos)
WINDOW_MINUTES = 5
POLL_SECONDS = 60

# Envío de alertas al syslog-ng (Docker expone 5140/udp)
SYSLOG_IP = "127.0.0.1"
SYSLOG_PORT = 5140

# Umbral de disparo de alerta (BAJO para pruebas)
# Cuando el flujo funcione, súbelo de nuevo a 0.75
SCORE_THRESHOLD = 0.10

# Regex para detectar throughput en tus logs "throughput"
RE_THROUGHPUT = re.compile(r"Throughput=([0-9]*\.?[0-9]+)")

# =========================
# UTILIDADES
# =========================
def to_ns(dt: datetime) -> int:
    """Convierte datetime a nanosegundos (formato Loki)."""
    return int(dt.timestamp() * 1e9)

def loki_query_range(query: str, start_dt: datetime, end_dt: datetime, limit: int = 5000) -> dict:
    """Consulta Loki por rango de tiempo."""
    params = {
        "query": query,
        "start": str(to_ns(start_dt)),
        "end": str(to_ns(end_dt)),
        "limit": str(limit),
        "direction": "BACKWARD",
    }
    r = requests.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, timeout=15)
    r.raise_for_status()
    return r.json()

def extract_lines(loki_json: dict):
    """Extrae [(timestamp_ns, line), ...] desde la respuesta de Loki."""
    out = []
    result = loki_json.get("data", {}).get("result", [])
    for stream in result:
        for ts_ns, line in stream.get("values", []):
            out.append((int(ts_ns), line))
    return out

def send_syslog(message: str):
    """
    Envía un mensaje en formato syslog simple por UDP al syslog-ng.
    OJO: syslog-ng te lo deja en ingested.log y luego promtail lo manda a Loki.
    """
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    host = "ai-engine"
    tag = "ai-detector"
    line = f"{ts} {host} {tag}: {message}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(line.encode("utf-8", errors="ignore"), (SYSLOG_IP, SYSLOG_PORT))
    finally:
        sock.close()

# =========================
# MÉTRICAS + “AI LIGERA”
# =========================
def compute_metrics(lines):
    """
    Calcula métricas simples desde logs:
    - total de líneas
    - tasa de logs/min
    - conteo de eventos de seguridad / errores
    - throughput promedio (si existe)
    """
    total = len(lines)
    security = 0
    errors = 0
    thr_vals = []

    for _, line in lines:
        l = line.lower()

        # Heurísticas simples
        if "security:" in l or "auth" in l:
            security += 1

        if "error" in l or "failed" in l or "deny" in l or "blocked" in l:
            errors += 1

        # Throughput (si viene en el log)
        m = RE_THROUGHPUT.search(line)
        if m:
            try:
                thr_vals.append(float(m.group(1)))
            except:
                pass

    minutes = max(WINDOW_MINUTES, 1)

    return {
        "total": total,
        "log_rate": total / minutes,
        "security": security,
        "sec_rate": security / minutes,
        "errors": errors,
        "err_rate": errors / minutes,
        "thr_avg": (sum(thr_vals) / len(thr_vals)) if thr_vals else None,
    }

def simple_score(metrics):
    """
    “AI ligera” (MVP): puntaje basado en reglas.
    Devuelve:
    - score 0..1
    - razones (lista)
    """
    score = 0.0
    reasons = []

    # Mucho volumen de logs
    if metrics["log_rate"] >= 20:
        score += 0.35
        reasons.append("high_log_rate")

    # Mucha actividad de seguridad
    if metrics["sec_rate"] >= 5:
        score += 0.35
        reasons.append("high_security_rate")

    # Muchos errores
    if metrics["err_rate"] >= 2:
        score += 0.20
        reasons.append("high_error_rate")

    # Throughput bajo (si aparece)
    if metrics["thr_avg"] is not None and metrics["thr_avg"] < 0.25:
        score += 0.30
        reasons.append("low_throughput")

    if score > 1.0:
        score = 1.0

    return score, reasons

# =========================
# MAIN LOOP
# =========================
def main():
    print("AI detector running. Ctrl+C to stop.", flush=True)
    print("Reading Loki logs and emitting AI_ALERT via syslog-ng...", flush=True)
    print(f"CONFIG: WINDOW_MINUTES={WINDOW_MINUTES}, POLL_SECONDS={POLL_SECONDS}, THRESHOLD={SCORE_THRESHOLD}", flush=True)

    while True:
        try:
            end = datetime.now(timezone.utc)
            start = end - timedelta(minutes=WINDOW_MINUTES)

            data = loki_query_range(QUERY, start, end)
            lines = extract_lines(data)
            metrics = compute_metrics(lines)
            score, reasons = simple_score(metrics)

            print(
                f"[{datetime.utcnow().isoformat()}Z] "
                f"total={metrics['total']} log_rate={metrics['log_rate']:.2f}/min "
                f"sec_rate={metrics['sec_rate']:.2f}/min err_rate={metrics['err_rate']:.2f}/min "
                f"thr_avg={metrics['thr_avg']} score={score:.2f} reasons={reasons}",
                flush=True
            )

            # Si supera el umbral, mandamos AI_ALERT al syslog-ng
            if score >= SCORE_THRESHOLD:
                msg = (
                    f"AI_ALERT severity=high score={score:.2f} window={WINDOW_MINUTES}m "
                    f"total={metrics['total']} sec={metrics['security']} errors={metrics['errors']} "
                    f"thr_avg={metrics['thr_avg']} reason=\"{','.join(reasons)}\""
                )
                send_syslog(msg)
                print(">>> SENT:", msg, flush=True)

        except Exception as e:
            print("ERROR:", e, flush=True)
            # También reportamos error como alerta de severidad media (para verlo en grafana)
            send_syslog(f"AI_ALERT severity=medium score=0.50 reason=\"ai_engine_error {str(e)}\"")

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    main()