# 🛡️ RansomWatch

A behavioral ransomware detection and neutralization tool with a real-time dashboard.

Unlike traditional antivirus software that relies on known signatures,
RansomWatch detects ransomware by analyzing **what it does** — not what it is.

---

## How It Works

RansomWatch runs two detection methods simultaneously:

### 1. File System Watcher
Monitors high-value user folders (Documents, Desktop, Pictures, Videos, Downloads)
in real time. Every file event is scored based on suspicious indicators:

| Event | Score |
|---|---|
| Mass file activity (10+ files in 5s) | +5 per event |
| File renamed to suspicious extension (`.locked`, `.encrypted`...) | +25 |
| Ransom note pattern detected (`readme_decrypt`, `how_to_recover`...) | +40 |
| High file entropy detected (likely encrypted content) | +30 |

When the cumulative score hits **70** → the responsible process is identified and killed.

### 2. Process Monitor
Runs in a background thread, scanning all running processes every 2 seconds.
If a single process is found touching an abnormal number of files inside
watched folders → it gets killed immediately, regardless of the score.

### Entropy Detection
Encrypted files have near-random byte distributions — high Shannon entropy (7.5+/8.0).
RansomWatch calculates the entropy of modified files in real time.
A sudden entropy spike on a document file is a strong indicator of encryption in progress.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, watchdog, psutil |
| Database | SQLite |
| Frontend | React, Vite |
| Config | python-dotenv |

---

## Project Structure

```
RansomWatch/
├── backend/
│   ├── main.py              # FastAPI server + detection engine
│   ├── database.py          # SQLite logging
│   ├── .env.example         # Config template
│   └── tests/
│       ├── simulate_ransomware.py   # Mass file creation simulator
│       └── simulate_entropy.py      # Encryption behavior simulator
└── frontend/
    ├── src/
    │   ├── App.jsx          # React dashboard
    │   └── index.css
    └── .env.example
```


---

## Installation

### Backend
```bash
cd backend
pip install fastapi uvicorn watchdog psutil python-dotenv
cp .env.example .env
uvicorn main:app --reload
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open **http://localhost:5173** to view the dashboard.

---

## Known Limitations

- **User-space only** — detection runs at the application level, not kernel level.
  A sophisticated ransomware could potentially bypass watchdog-based monitoring.
- **Process identification** — fast-executing processes may exit before they can be identified and killed. The file events are still logged and scored.
- **False positives** — compression software or backup tools that rapidly modify many files could trigger alerts. Naturally high-entropy file types (`.zip`, `.jpg`, `.mp4`) are excluded from entropy scoring.

---

## What I'd Add With More Time

- Kernel-level monitoring via Windows driver
- Automatic file rollback before process kill
- Machine learning on scoring weights per machine baseline
- Email/SMS alert on threat detection
