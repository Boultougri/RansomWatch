import time
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict

WATCHED_FOLDER = "C:/watchdog/test_folder"

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

ALERT_THRESHOLD = 70
FILE_TOUCH_THRESHOLD = 15  # only files inside watched folder now, so 15 is reasonable

event_tracker = defaultdict(list)
process_file_counts = defaultdict(set)
score = 0


# ─────────────────────────────────────────
#  PROCESS KILLER
# ─────────────────────────────────────────

def kill_process_by_pid(pid, name, reason):
    try:
        proc = psutil.Process(pid)
        proc.kill()
        print(f"\n{'='*50}")
        print(f"🚨 THREAT KILLED")
        print(f"   Process : {name} (PID: {pid})")
        print(f"   Reason  : {reason}")
        print(f"✅  Process killed successfully")
        print(f"{'='*50}\n")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"❌  Could not kill {name} (PID: {pid}): {e}")


# ─────────────────────────────────────────
#  METHOD 1 — FILE SYSTEM WATCHER
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


def calculate_score(event_type, filepath):
    global score

    now = time.time()
    event_tracker[filepath].append(now)

    # Clean up events older than 5 seconds
    for key in list(event_tracker.keys()):
        event_tracker[key] = [t for t in event_tracker[key] if now - t < 5]

    total_recent_events = sum(len(v) for v in event_tracker.values())

    # Rule 1 — mass file activity
    if total_recent_events > 10:
        score += 5
        print(f"  ⚠️  High file activity: {total_recent_events} events in 5s (+5)")

    # Rule 2 — suspicious extension
    ext = "." + filepath.split(".")[-1].lower() if "." in filepath else ""
    if ext in SUSPICIOUS_EXTENSIONS:
        score += 25
        print(f"  ⚠️  Suspicious extension: {ext} (+25)")

    # Rule 3 — ransom note pattern
    filename = filepath.split("/")[-1].split("\\")[-1].lower()
    if any(pattern in filename for pattern in RANSOM_NOTE_PATTERNS):
        score += 40
        print(f"  ⚠️  Ransom note pattern: {filename} (+40)")

    # Rule 4 — renamed to suspicious extension
    if event_type == "RENAMED" and any(
        filepath.lower().endswith(e) for e in SUSPICIOUS_EXTENSIONS
    ):
        score += 25
        print(f"  ⚠️  Renamed to suspicious extension (+25)")

    # Threshold hit
    if score >= ALERT_THRESHOLD:
        print(f"\n🚨 Score threshold hit: {score}")
        proc = find_process_using_file(filepath)
        if proc:
            kill_process_by_pid(
                proc.info['pid'],
                proc.info['name'],
                f"File watcher score: {score}"
            )
        else:
            print(f"⚠️  Could not identify process — process may have already exited")
            print(f"   Suspicious file: {filepath}\n")
        score = 0
        event_tracker.clear()


class RansomwareWatcher(FileSystemEventHandler):

    def on_modified(self, event):
        if not event.is_directory:
            print(f"[MODIFIED] {event.src_path}")
            calculate_score("MODIFIED", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"[CREATED]  {event.src_path}")
            calculate_score("CREATED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[DELETED]  {event.src_path}")
            calculate_score("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            print(f"[RENAMED]  {event.src_path}  →  {event.dest_path}")
            calculate_score("RENAMED", event.dest_path)


# ─────────────────────────────────────────
#  METHOD 2 — PROCESS MONITOR (background thread)
# ─────────────────────────────────────────

def monitor_processes():
    """Continuously scan all running processes for suspicious file activity"""
    print("🔍 Process monitor started\n")

    WHITELIST = {
        "system", "svchost.exe", "explorer.exe",
        "watcher.py", "python.exe", "pythonw.exe",
        "code.exe", "opera.exe", "chrome.exe",
        "firefox.exe", "msedge.exe", "brave.exe",
        "discord.exe", "spotify.exe", "steam.exe",
        "antivirus", "defender", "winword.exe",
        "excel.exe", "notepad.exe", "powershell.exe",
        "cmd.exe", "taskhostw.exe", "runtimebroker.exe"
    }

    while True:
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                name = proc.info['name'].lower()
                pid = proc.info['pid']
                open_files = proc.info['open_files']

                # Skip whitelisted processes
                if any(w in name for w in WHITELIST):
                    continue

                if open_files:
                    # ⚠️ Only count files INSIDE the watched folder
                    watched_files = [
                        f.path for f in open_files
                        if WATCHED_FOLDER.lower().replace("/", "\\")
                        in f.path.lower()
                    ]

                    process_file_counts[pid].update(watched_files)
                    count = len(process_file_counts[pid])

                    if count > FILE_TOUCH_THRESHOLD:
                        print(f"\n⚠️  [PROCESS MONITOR] Suspicious process detected:")
                        print(f"   Name : {proc.info['name']}")
                        print(f"   PID  : {pid}")
                        print(f"   Files touched in watched folder: {count}")

                        kill_process_by_pid(
                            pid,
                            proc.info['name'],
                            f"Touched {count} files in watched folder "
                            f"(threshold: {FILE_TOUCH_THRESHOLD})"
                        )

                        process_file_counts.pop(pid, None)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(2)


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print(f"👁️  Watching folder : {WATCHED_FOLDER}")
    print(f"🎯  Alert threshold : {ALERT_THRESHOLD} points")
    print(f"📊  Process threshold: {FILE_TOUCH_THRESHOLD} files\n")

    # Start process monitor in background thread
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    process_thread.start()

    # Start file watcher
    event_handler = RansomwareWatcher()
    observer = Observer()
    observer.schedule(event_handler, WATCHED_FOLDER, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 Watcher stopped")

    observer.join()