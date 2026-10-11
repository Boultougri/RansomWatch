from dotenv import load_dotenv
import os

load_dotenv()

ALERT_THRESHOLD      = int(os.getenv("ALERT_THRESHOLD", 70))
FILE_TOUCH_THRESHOLD = int(os.getenv("FILE_TOUCH_THRESHOLD", 15))

SUSPICIOUS_EXTENSIONS = [
    ".locked", ".encrypted", ".enc", ".crypto",
    ".crypt", ".crypted", ".crinf", ".r5a",
    ".XRNT", ".XTBL", ".R16M01D05", ".pzdc",
    ".LOL!", ".OMG!", ".RDM", ".RRK",
    ".encryptedRSA", ".crjoker", ".EnCiPhErEd",
    ".0x0", ".bleep", ".1999", ".wallet"
]

RANSOM_NOTE_PATTERNS = [
    "readme", "decrypt", "how_to", "restore",
    "recover", "ransom", "help_decrypt", "attention"
]

# These extensions are naturally high entropy — skip entropy check
ENTROPY_SKIP_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".mp3", ".mp4",
    ".avi", ".mkv", ".jpg", ".jpeg", ".png", ".gif"
}

import time
import threading
import psutil
import math
import sqlite3
from database import init_db, insert_event, insert_alert, insert_killed
from database import get_events as db_get_events
from database import get_alerts as db_get_alerts
from database import get_killed as db_get_killed
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
#  SHARED STATE
# ─────────────────────────────────────────

state = {
    "events": [],
    "alerts": [],
    "score": 0,
    "killed_processes": [],
    "watching": True
}

event_tracker        = defaultdict(list)
process_file_counts  = defaultdict(set)
TRUSTED_PIDS         = set()


# ─────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────

def get_user_folders():
    """Automatically detect high-value user folders to watch"""
    home    = os.path.expanduser("~")
    targets = ["Documents", "Desktop", "Pictures", "Videos", "Downloads"]
    folders = [
        os.path.join(home, folder)
        for folder in targets
        if os.path.exists(os.path.join(home, folder))
    ]

    # Add test folder if it exists (remove this in production)
    test_folder = os.getenv("TEST_FOLDER", "")
    if test_folder and os.path.exists(test_folder):
        folders.append(test_folder)

    return folders


def build_trusted_snapshot():
    """Trust every process already running at startup"""
    global TRUSTED_PIDS
    for proc in psutil.process_iter(['pid']):
        try:
            TRUSTED_PIDS.add(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    print(f"✅ Trusted snapshot: {len(TRUSTED_PIDS)} existing processes whitelisted")


def log_event(event_type, filepath):
    now = datetime.now().strftime("%H:%M:%S")
    # Still keep in memory for speed
    state["events"].append({
        "type": event_type,
        "file": filepath,
        "time": now
    })
    if len(state["events"]) > 100:
        state["events"].pop(0)
    # Also persist to DB
    insert_event(event_type, filepath, now)


def log_alert(reason, filepath, process_name=None):
    now = datetime.now().strftime("%H:%M:%S")
    state["alerts"].append({
        "reason":  reason,
        "file":    filepath,
        "process": process_name or "Unknown",
        "time":    now
    })
    insert_alert(reason, filepath, process_name, now)


def kill_process_by_pid(pid, name, reason, filepath=""):
    try:
        proc = psutil.Process(pid)
        proc.kill()
        now = datetime.now().strftime("%H:%M:%S")
        state["killed_processes"].append({
            "pid":    pid,
            "name":   name,
            "reason": reason,
            "time":   now
        })
        insert_killed(pid, name, reason, now)
        log_alert(reason, filepath, name)
        print(f"🚨 Killed {name} (PID: {pid}) — {reason}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"❌ Could not kill {name}: {e}")


# ─────────────────────────────────────────
#  METHOD 1 — FILE WATCHER
# ─────────────────────────────────────────

def find_process_using_file(filepath):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            open_files = proc.info['open_files']
            if open_files:
                for f in open_files:
                    if filepath.lower() in f.path.lower():
                        return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file — 0 (ordered) to 8 (random/encrypted)"""
    try:
        with open(filepath, "rb") as f:
            data = f.read(4096)  # first 4KB is enough to judge

        if not data:
            return 0

        frequency = defaultdict(int)
        for byte in data:
            frequency[byte] += 1

        length  = len(data)
        entropy = 0
        for count in frequency.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    except (PermissionError, FileNotFoundError, OSError):
        return 0

def calculate_score(event_type, filepath):
    now = time.time()
    event_tracker[filepath].append(now)

    for key in list(event_tracker.keys()):
        event_tracker[key] = [t for t in event_tracker[key] if now - t < 5]

    total_recent_events = sum(len(v) for v in event_tracker.values())

    if total_recent_events > 10:
        state["score"] += 5

    ext = "." + filepath.split(".")[-1].lower() if "." in filepath else ""
    if ext in SUSPICIOUS_EXTENSIONS:
        state["score"] += 25

    filename = filepath.split("/")[-1].split("\\")[-1].lower()
    if any(pattern in filename for pattern in RANSOM_NOTE_PATTERNS):
        state["score"] += 40

    if event_type == "RENAMED" and any(
        filepath.lower().endswith(e) for e in SUSPICIOUS_EXTENSIONS
    ):
        state["score"] += 25
    
        # Rule 5 — high entropy after modification (file likely encrypted)
    if event_type == "MODIFIED":
        entropy = calculate_entropy(filepath)
        if entropy > 7.5:
            state["score"] += 30
            print(f"  ⚠️  High entropy detected: {entropy}/8.0 (+30)")

    if state["score"] >= ALERT_THRESHOLD:
        print(f"🚨 Score threshold hit: {state['score']}")
        proc = find_process_using_file(filepath)
        if proc:
            kill_process_by_pid(
                proc.info['pid'],
                proc.info['name'],
                f"Behavior score: {state['score']}",
                filepath
            )
        else:
            log_alert(
                f"Score threshold hit ({state['score']}) — process not found",
                filepath
            )
        state["score"] = 0
        event_tracker.clear()


class RansomwareWatcher(FileSystemEventHandler):

    def on_modified(self, event):
        if not event.is_directory:
            log_event("MODIFIED", event.src_path)
            calculate_score("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            log_event("CREATED", event.src_path)
            calculate_score("CREATED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            log_event("DELETED", event.src_path)
            calculate_score("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            log_event("RENAMED", event.dest_path)
            calculate_score("RENAMED", event.dest_path)


# ─────────────────────────────────────────
#  METHOD 2 — PROCESS MONITOR
# ─────────────────────────────────────────

def monitor_processes():
    print("🔍 Process monitor started")
    watched_folders = get_user_folders()

    while True:
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                pid        = proc.info['pid']
                name       = proc.info['name']
                open_files = proc.info['open_files']

                # Skip trusted processes
                if pid in TRUSTED_PIDS:
                    continue

                if open_files:
                    watched_files = [
                        f.path for f in open_files
                        if any(
                            folder.lower().replace("/", "\\") in f.path.lower()
                            for folder in watched_folders
                        )
                    ]
                    process_file_counts[pid].update(watched_files)
                    count = len(process_file_counts[pid])

                    if count > FILE_TOUCH_THRESHOLD:
                        kill_process_by_pid(
                            pid, name,
                            f"Touched {count} files in watched folders"
                        )
                        process_file_counts.pop(pid, None)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(2)


# ─────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────

@app.get("/status")
def get_status():
    return {
        "watching":       state["watching"],
        "watched_folders": get_user_folders(),
        "score":          state["score"],
        "alert_threshold": ALERT_THRESHOLD,
    }

@app.get("/events")
def get_events():
    return db_get_events()

@app.get("/alerts")
def get_alerts():
    return db_get_alerts()

@app.get("/killed")
def get_killed():
    return db_get_killed()


# ─────────────────────────────────────────
#  STARTUP
# ─────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()  # ← initialize database first
    build_trusted_snapshot()

    folders = get_user_folders()

    t = threading.Thread(target=monitor_processes, daemon=True)
    t.start()

    event_handler = RansomwareWatcher()
    observer      = Observer()

    for folder in folders:
        observer.schedule(event_handler, folder, recursive=True)
        print(f"👁️  Watching: {folder}")

    observer.start()