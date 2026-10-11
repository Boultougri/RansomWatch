import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "ransomwatch.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    return conn


def init_db():
    """Create tables if they don't exist"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            type      TEXT NOT NULL,
            file      TEXT NOT NULL,
            time      TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            reason    TEXT NOT NULL,
            file      TEXT NOT NULL,
            process   TEXT DEFAULT 'Unknown',
            time      TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS killed_processes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            pid       INTEGER NOT NULL,
            name      TEXT NOT NULL,
            reason    TEXT NOT NULL,
            time      TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized")


def insert_event(event_type, filepath, time):
    conn = get_connection()
    conn.execute(
        "INSERT INTO events (type, file, time) VALUES (?, ?, ?)",
        (event_type, filepath, time)
    )
    conn.commit()
    conn.close()


def insert_alert(reason, filepath, process_name, time):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (reason, file, process, time) VALUES (?, ?, ?, ?)",
        (reason, filepath, process_name or "Unknown", time)
    )
    conn.commit()
    conn.close()


def insert_killed(pid, name, reason, time):
    conn = get_connection()
    conn.execute(
        "INSERT INTO killed_processes (pid, name, reason, time) VALUES (?, ?, ?, ?)",
        (pid, name, reason, time)
    )
    conn.commit()
    conn.close()


def get_events(limit=100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alerts():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_killed():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM killed_processes ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]