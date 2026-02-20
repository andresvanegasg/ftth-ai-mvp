import csv
import socket
import sys
from datetime import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 5140

def pick(row, candidates):
    for c in candidates:
        if c in row and row[c] not in (None, "", "NA", "NaN"):
            return row[c]
    return None

def normalize_ts(value: str) -> str:
    """
    Intenta convertir un timestamp cualquiera a formato syslog: 'Feb 19 12:34:56'
    Si no puede, usa la hora actual.
    """
    if not value:
        return datetime.now().strftime("%b %d %H:%M:%S")
    v = value.strip()
    # Intentos comunes
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(v, fmt)
            return dt.strftime("%b %d %H:%M:%S")
        except ValueError:
            pass
    # Si ya parece syslog, lo dejamos
    if len(v) >= 15 and v[3] == " ":
        return v[:15]
    return datetime.now().strftime("%b %d %H:%M:%S")

def csv_to_syslog_lines(csv_path: str, source_tag: str, limit: int = 0):
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            # Campos típicos
            ts = pick(row, ["timestamp", "time", "date", "Date", "Time", "Datetime", "Timestamp"])
            host = pick(row, ["host", "device", "Device", "hostname", "Host", "source", "Source", "src_ip", "Source IP"])
            sev  = pick(row, ["severity", "level", "Severity", "Level", "priority", "Priority"])
            evt  = pick(row, ["event", "event_type", "Event", "Event Type", "action", "Action", "log_type", "Log Type"])
            msg  = pick(row, ["message", "Message", "description", "Description", "msg", "log", "Log", "details", "Details"])

            # Construcción de un mensaje "compatible"
            ts_syslog = normalize_ts(ts)
            host = (host or "unknown-host").replace(" ", "_")
            sev = (sev or "info").lower()
            evt = (evt or source_tag).replace(" ", "_")

            # Si no hay message, construye uno con el resto de columnas
            if not msg:
                # compacta clave=valor para que sea legible
                msg = " ".join([f"{k}={str(v).strip()}" for k, v in row.items() if v not in (None, "", "NA", "NaN")][:12])
                if not msg:
                    msg = "no_message"

            # Formato syslog simple:
            # <timestamp> <host> <app>[pid]: <mensaje>
            line = f"{ts_syslog} {host} {source_tag}: severity={sev} event={evt} {msg}"
            yield line

            count += 1
            if limit and count >= limit:
                break

def send_udp(lines):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    for line in lines:
        sock.sendto(line.encode("utf-8", errors="ignore"), (UDP_IP, UDP_PORT))
        sent += 1
    sock.close()
    return sent

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 src/csv_to_syslog.py <ruta_csv> [tag] [limit]")
        sys.exit(1)

    csv_path = sys.argv[1]
    tag = sys.argv[2] if len(sys.argv) >= 3 else "zenodo"
    limit = int(sys.argv[3]) if len(sys.argv) >= 4 else 0

    lines = csv_to_syslog_lines(csv_path, tag, limit=limit)
    sent = send_udp(lines)
    print(f"OK: enviados {sent} logs desde {csv_path} a syslog-ng (UDP {UDP_PORT})")

if __name__ == "__main__":
    main()