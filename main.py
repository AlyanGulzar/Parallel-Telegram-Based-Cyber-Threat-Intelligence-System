import asyncio
import re
import time
import logging
import threading
import signal
from multiprocessing import Process, Queue, cpu_count, Semaphore, Manager
from telethon import TelegramClient, events
from flask import Flask, render_template_string
import socks

# ---------------------------
# USER CONFIG
# ---------------------------
API_ID = 39161944
API_HASH = "b05bd5bedbd64f6c4e3ec14fe636a8e6"
SESSION_NAME = "cti_session"
DASH_PORT = 5000

# Visualization timing (demo-friendly)
ANALYSIS_DELAY = 0.8
CRITICAL_DELAY = 1.2

# Ask user how many workers to spawn (bounded by CPU cores)
try:
    raw = input(f"Enter number of workers (1–{cpu_count()}), press Enter for default (min(4, cores)): ").strip()
    NUM_WORKERS = int(raw) if raw else min(4, cpu_count())
except ValueError:
    print("[ERROR] Invalid worker count. Defaulting to min(4, cpu_count()).")
    NUM_WORKERS = min(4, cpu_count())

NUM_WORKERS = max(1, min(NUM_WORKERS, cpu_count()))
print(f"[SOC] Starting with {NUM_WORKERS} worker processes")

# ---------------------------
# CTI / SIGNATURES
# ---------------------------
SIGNATURES = [
    "malware", "ransomware", "rat", "exploit", "cve",
    "zero-day", "database", "leak", "backdoor",
    "phishing", "ddos", "attack", "breach"
]

PATTERNS = {
    "IP": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "CVE": r"CVE-\d{4}-\d{4,7}",
    "ONION": r"[a-z2-7]{16,56}\.onion"
}

# ---------------------------
# IPC / SHARED STATE
# ---------------------------
input_queue = Queue()
manager = Manager()
SHARED_THREATS = manager.list()     # shared list of detected threats (exclusive writes)
WORKER_STATUS = manager.dict()      # worker_name -> status
SEMAPHORE_OWNER = manager.Value('s', "")  # who currently holds write lock
SEMAPH = Semaphore(1)               # exclusive write semaphore

# Keep process references so we can stop them on shutdown
WORKER_PROCS = []

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PDC-CTI")

# ---------------------------
# Analysis helpers (PDC: concurrent read)
# ---------------------------
def analyze_text(text: str):
    """
    Concurrent read of SIGNATURES (CREW model allows concurrent reads).
    Returns list of findings.
    """
    if not text:
        return []
    t = text.lower()
    findings = [s for s in SIGNATURES if s in t]
    for label, pat in PATTERNS.items():
        if re.search(pat, text):
            findings.append(label)
    return findings

def calculate_severity(text: str, findings: list):
    """
    Simple scoring to map to LOW/MEDIUM/HIGH/CRITICAL
    """
    if not findings:
        return "LOW"
    score = 0
    tl = text.lower()
    critical_kw = {"exploit", "ransomware", "zero-day", "0day", "cve"}
    attack_kw = {"attack", "breach", "ddos", "compromise"}
    for k in critical_kw:
        if k in tl:
            score += 3
    for k in attack_kw:
        if k in tl:
            score += 2
    for f in findings:
        if f in ("IP", "CVE", "ONION"):
            score += 2
    score += max(0, len(findings) - 1)
    if score >= 9:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"

# ---------------------------
# Worker process (Parallel)
# ---------------------------
def worker_process(worker_name, in_q, shared_threats, status_dict, sem, sem_owner_proxy):
    """
    Worker loop:
    - Pull message from queue (consumer)
    - Concurrently read SIGNATURES (no lock)
    - If findings -> attempt exclusive write by acquiring semaphore
    - Write into shared_threats while holding semaphore (critical section)
    - Instrument semaphore owner for dashboard visibility
    """
    status_dict[worker_name] = "IDLE"
    logger.info("%s started", worker_name)

    while True:
        try:
            item = in_q.get()
            if item == "STOP":
                status_dict[worker_name] = "STOPPED"
                break

            # Processing (simulate analysis time so UI can show state)
            status_dict[worker_name] = "PROCESSING"
            time.sleep(ANALYSIS_DELAY)

            text = item.get("text", "")
            findings = analyze_text(text)
            if not findings:
                status_dict[worker_name] = "IDLE"
                continue

            severity = calculate_severity(text, findings)

            # Request exclusive write (synchronize)
            status_dict[worker_name] = "WAITING"
            sem.acquire()
            try:
                status_dict[worker_name] = "IN_CRITICAL"
                sem_owner_proxy.value = worker_name

                # Hold lock for demo visibility, then append
                time.sleep(CRITICAL_DELAY)

                shared_threats.append({
                    "time": time.strftime("%H:%M:%S"),
                    "chat_title": item.get("chat_title", "Unknown"),
                    "chat_id": item.get("chat_id", "Unknown"),
                    "sender_username": item.get("sender_username", "NoUsername"),
                    "sender_id": item.get("sender_id", "Unknown"),
                    "text": text,
                    "findings": findings,
                    "severity": severity,
                    "worker": worker_name
                })
            finally:
                sem_owner_proxy.value = ""
                sem.release()
                status_dict[worker_name] = "IDLE"

        except Exception as e:
            # Robust error handling (log and set worker status to ERROR)
            logger.exception("Worker %s encountered exception: %s", worker_name, e)
            status_dict[worker_name] = "ERROR"

    logger.info("%s exiting", worker_name)

# ---------------------------
# Telethon: Producer (async)
# ---------------------------
client = TelegramClient(
    SESSION_NAME,
    API_ID,
    API_HASH,
    proxy=(socks.SOCKS5, "127.0.0.1", 9050)
)

@client.on(events.NewMessage(incoming=True, outgoing=True))
async def on_new_message(event):
    try:
        """
        Telethon event handler: run in asyncio context.
        Put minimal payload into multiprocessing queue for workers.
        We include chat_title and chat_id for analyst context in alerts.
        """
        text = event.raw_text if hasattr(event, "raw_text") else ""
        if not text:
            return

        # Resolve chat metadata safely
        try:
            chat = await event.get_chat()
            chat_title = getattr(chat, "title", "Private/Unknown")
        except Exception:
            chat_title = "Unknown"

        # Resolve sender safely (NO crash possible)
        try:
            sender = await event.get_sender()
            sender_username = sender.username if sender and sender.username else "NoUsername"
        except Exception:
            sender_username = "NoUsername"

        payload = {
            "chat_title": chat_title,
            "chat_id": getattr(event, "chat_id", "Unknown"),
            "sender_username": sender_username,
            "text": text[:2000]
        }

        # Producer: push to queue
        input_queue.put(payload)

    except Exception as e:
        logger.exception("Unhandled exception in on_new_message: %s", e)


# ---------------------------
# Flask Dashboard (thread)
# ---------------------------
app = Flask("cti_dashboard")

DASH_HTML = """
<!doctype html>
<html>
<head>
<meta http-equiv="refresh" content="1">
<meta charset="utf-8">
<title>Parallel Telegram CTI SOC - PRAM View</title>
<style>
  body{background:#071024;color:#e6eef6;font-family:Segoe UI,Roboto,Arial;padding:18px;margin:0}
  h1{color:#00ffd1;margin:8px 0 12px 0}
  .grid{display:grid;grid-template-columns:2.5fr 1fr;gap:14px;padding:12px}
  .panel{background:#0f1a2b;padding:14px;border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,0.4)}
  .threat{background:#081223;padding:12px;border-left:8px solid #ff5c5c;margin-bottom:10px;border-radius:6px}
  .CRITICAL{border-color:#8b0000}
  .HIGH{border-color:#ff3b3b}
  .MEDIUM{border-color:#ff9f1c}
  .LOW{border-color:#2ecc71}
  .small{font-size:12px;color:#bcd6e6}
  /* Worker/status coloring we restore and enhance (do not change IDLE) */
  .worker-name { color:#4fc3f7; font-weight:600 }
  .status-header { color:#9ad9ff }  
  .semaphore-title { color:#b388ff }
  .locked { color:#ff6b6b; font-weight:700 }
  .crew-note { color:#6ee7e7; font-size:12px }
  .idle{color:#9ae6a5}
  .processing{color:#ffd480}
  .critical{color:#ff8b8b}
  table{width:100%;border-collapse:collapse}
  th,td{padding:6px 8px;text-align:left}
</style>
</head>
<body>
  <h1>Parallel Telegram CTI SOC - Core / PRAM View</h1>

  <div class="grid">
    <div class="panel">
      <h3>Detected Threats (most recent first)</h3>
      {% if threats %}
        {% for t in threats[::-1] %}
          <div class="threat {{ t.severity }}">
            <div style="font-weight:700;letter-spacing:0.2px">{{ t.severity }} — {{ t.chat_title }} ({{ t.chat_id }})</div>
            <div class="small">{{ t.time }} | worker: {{ t.worker }}</div>
            <div style="margin-top:8px" class="small">Indicators: {{ t.findings }}</div>
            <div style="margin-top:8px">{{ t.text }}</div>
          </div>
        {% endfor %}
      {% else %}
        <div>No threats detected yet.</div>
      {% endif %}
    </div>

    <div class="panel">
      <h3 class="status-header">Worker / Core Status</h3>
      <table>
        <thead><tr><th>Worker</th><th>Status</th></tr></thead>
        <tbody>
        {% for k,v in workers.items() %}
          <tr>
            <td><span class="worker-name">{{ k }}</span></td>
            <td>
              {% if v == "IDLE" %}
                <span class="idle">{{ v }}</span>
              {% elif v == "PROCESSING" %}
                <span class="processing">{{ v }}</span>
              {% elif v == "WAITING" %}
                <span class="processing">{{ v }}</span>
              {% elif v == "IN_CRITICAL" %}
                <span class="critical">{{ v }}</span>
              {% elif v == "ERROR" %}
                <span style="color:#ffb86b;font-weight:700">{{ v }}</span>
              {% else %}
                {{ v }}
              {% endif %}
            </td>
          </tr>
        {% endfor %}
        </tbody>
      </table>

      <h3 class="semaphore-title" style="margin-top:12px">Semaphore (Exclusive Write)</h3>
      <div style="margin:6px 0">
        <strong>Locked by:</strong>
        {% if semaphore %}
          <span class="locked">{{ semaphore }}</span>
        {% else %}
          <b>None</b>
        {% endif %}
      </div>
      <div class="crew-note">CREW model: concurrent reads allowed; exclusive writes enforced by semaphore</div>
    </div>
  </div>

</body>
</html>
"""

@app.route("/")
def dashboard():
    # Ensure deterministic ordering of workers (worker_1 ... worker_N)
    ordered_workers = dict(sorted(WORKER_STATUS.items(), key=lambda x: int(x[0].split("_")[1])))
    return render_template_string(
        DASH_HTML,
        threats=list(SHARED_THREATS),
        workers=ordered_workers,
        semaphore=SEMAPHORE_OWNER.value
    )

def run_dashboard():
    # Run Flask in a background thread (non-blocking)
    app.run("127.0.0.1", DASH_PORT, debug=False, use_reloader=False)

# ---------------------------
# Main orchestration & graceful shutdown
# ---------------------------
async def main():
    # Start dashboard thread
    dash_thread = threading.Thread(target=run_dashboard, daemon=True)
    dash_thread.start()
    logger.info("Dashboard started at http://127.0.0.1:%d", DASH_PORT)

    # Start worker processes
    for i in range(NUM_WORKERS):
        name = f"worker_{i+1}"
        WORKER_STATUS[name] = "IDLE"
        p = Process(target=worker_process, args=(name, input_queue, SHARED_THREATS, WORKER_STATUS, SEMAPH, SEMAPHORE_OWNER), daemon=True)
        p.start()
        WORKER_PROCS.append(p)
        logger.info("Started %s (pid=%s)", name, p.pid)

  


    # Start Telethon and listen; handle cancellations gracefully
    try:
        await client.start(phone=lambda: input("📱 Enter phone number or bot token: "))
        logger.info("Telegram client started; listening for new messages...")
        try:
            await client.run_until_disconnected()
        except asyncio.CancelledError:
            logger.info("Telegram listener cancelled (graceful shutdown)")
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received (graceful shutdown)")
    except Exception as e:
        logger.exception("Failed to start Telegram client: %s", e)
    finally:
        # Graceful shutdown: notify workers and terminate processes
        logger.info("Shutting down workers and cleaning up...")
        for _ in WORKER_PROCS:
            input_queue.put("STOP")
        time.sleep(0.5)
        for p in WORKER_PROCS:
            try:
                if p.is_alive():
                    p.terminate()
            except Exception:
                pass
        # Disconnect Telethon client
        try:
            await client.disconnect()
        except Exception:
            pass
        logger.info("Shutdown complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Final catch if signal reached here
        logger.info("KeyboardInterrupt caught in __main__, exiting cleanly.")
