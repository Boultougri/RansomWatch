import { useState, useEffect } from "react"
import axios from "axios"

const API = import.meta.env.VITE_API_URL

function App() {
  const [status, setStatus]   = useState(null)
  const [events, setEvents]   = useState([])
  const [alerts, setAlerts]   = useState([])
  const [killed, setKilled]   = useState([])

  // Poll the API every 2 seconds
  useEffect(() => {
    const fetch_data = async () => {
      try {
        const [s, e, a, k] = await Promise.all([
          axios.get(`${API}/status`),
          axios.get(`${API}/events`),
          axios.get(`${API}/alerts`),
          axios.get(`${API}/killed`),
        ])
        setStatus(s.data)
        setEvents([...e.data].reverse())   // newest first
        setAlerts([...a.data].reverse())
        setKilled([...k.data].reverse())
      } catch (err) {
        console.error("API unreachable", err)
      }
    }

    fetch_data()
    const interval = setInterval(fetch_data, 2000)
    return () => clearInterval(interval)
  }, [])

  const scoreColor = status
    ? status.score > 50 ? "#ff4444"
    : status.score > 25 ? "#ffaa00"
    : "#00cc66"
    : "#00cc66"

  return (
    <div style={styles.app}>

      {/* HEADER */}
      <div style={styles.header}>
        <h1 style={styles.title}>🛡️ RansomWatch</h1>
        <span style={styles.subtitle}>Ransomware Behavior Monitor</span>
      </div>

      {/* STATUS BAR */}
      {status && (
        <div style={styles.statusBar}>
          <div style={styles.statusItem}>
            <span style={styles.label}>Status</span>
            <span style={{ ...styles.badge, background: "#00cc66" }}>
              ● Watching
            </span>
          </div>
          <div style={styles.statusItem}>
    <span style={styles.label}>Watching</span>
    {status.watched_folders?.map((f, i) => (
        <span key={i} style={styles.mono}>{f}</span>
    ))}
</div>
          <div style={styles.statusItem}>
            <span style={styles.label}>Threat Score</span>
            <span style={{ ...styles.badge, background: scoreColor }}>
              {status.score} / {status.alert_threshold}
            </span>
          </div>
          <div style={styles.statusItem}>
            <span style={styles.label}>Alerts</span>
            <span style={styles.mono}>{alerts.length}</span>
          </div>
          <div style={styles.statusItem}>
            <span style={styles.label}>Killed</span>
            <span style={styles.mono}>{killed.length}</span>
          </div>
        </div>
      )}

      <div style={styles.grid}>

        {/* ALERTS */}
        <div style={styles.card}>
          <h2 style={styles.cardTitle}>🚨 Alerts</h2>
          {alerts.length === 0
            ? <p style={styles.empty}>No alerts yet</p>
            : alerts.map((a, i) => (
              <div key={i} style={styles.alertRow}>
                <div style={styles.rowTime}>{a.time}</div>
                <div style={styles.rowMain}>
                  <span style={styles.alertReason}>{a.reason}</span>
                  <span style={styles.rowFile}>{a.file}</span>
                  {a.process !== "Unknown" &&
                    <span style={styles.pill}>⚡ {a.process}</span>
                  }
                </div>
              </div>
            ))
          }
        </div>

        {/* KILLED PROCESSES */}
        <div style={styles.card}>
          <h2 style={styles.cardTitle}>💀 Killed Processes</h2>
          {killed.length === 0
            ? <p style={styles.empty}>No processes killed yet</p>
            : killed.map((k, i) => (
              <div key={i} style={styles.killedRow}>
                <div style={styles.rowTime}>{k.time}</div>
                <div style={styles.rowMain}>
                  <span style={styles.killedName}>{k.name}</span>
                  <span style={styles.rowFile}>PID: {k.pid}</span>
                  <span style={styles.rowFile}>{k.reason}</span>
                </div>
              </div>
            ))
          }
        </div>

        {/* FILE EVENTS */}
        <div style={{ ...styles.card, gridColumn: "1 / -1" }}>
          <h2 style={styles.cardTitle}>📁 File Events (live)</h2>
          {events.length === 0
            ? <p style={styles.empty}>No events yet</p>
            : events.slice(0, 50).map((e, i) => (
              <div key={i} style={styles.eventRow}>
                <span style={styles.rowTime}>{e.time}</span>
                <span style={{
                  ...styles.eventType,
                  background:
                    e.type === "CREATED"  ? "#1a3a2a" :
                    e.type === "MODIFIED" ? "#1a2a3a" :
                    e.type === "DELETED"  ? "#3a1a1a" :
                    "#2a1a3a"
                }}>
                  {e.type}
                </span>
                <span style={styles.mono}>{e.file}</span>
              </div>
            ))
          }
        </div>

      </div>
    </div>
  )
}

const styles = {
  app: {
    minHeight: "100vh",
    background: "#0a0a0f",
    color: "#e0e0e0",
    fontFamily: "'Segoe UI', sans-serif",
    padding: "0 0 40px 0"
  },
  header: {
    background: "#12121a",
    borderBottom: "1px solid #222",
    padding: "20px 32px",
    display: "flex",
    alignItems: "center",
    gap: 16
  },
  title: {
    margin: 0,
    fontSize: 24,
    color: "#fff",
    fontWeight: 700
  },
  subtitle: {
    color: "#666",
    fontSize: 14
  },
  statusBar: {
    background: "#12121a",
    borderBottom: "1px solid #1a1a2a",
    padding: "12px 32px",
    display: "flex",
    gap: 32,
    flexWrap: "wrap",
    alignItems: "center"
  },
  statusItem: {
    display: "flex",
    flexDirection: "column",
    gap: 4
  },
  label: {
    fontSize: 11,
    color: "#555",
    textTransform: "uppercase",
    letterSpacing: 1
  },
  badge: {
    padding: "2px 10px",
    borderRadius: 12,
    fontSize: 13,
    fontWeight: 600,
    color: "#fff"
  },
  mono: {
    fontFamily: "monospace",
    fontSize: 13,
    color: "#aaa"
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 20,
    padding: "24px 32px"
  },
  card: {
    background: "#12121a",
    border: "1px solid #1e1e2e",
    borderRadius: 12,
    padding: 20,
    maxHeight: 380,
    overflowY: "auto"
  },
  cardTitle: {
    margin: "0 0 16px 0",
    fontSize: 15,
    fontWeight: 600,
    color: "#fff"
  },
  empty: {
    color: "#444",
    fontSize: 13,
    fontStyle: "italic"
  },
  alertRow: {
    display: "flex",
    gap: 12,
    padding: "8px 0",
    borderBottom: "1px solid #1a1a2a"
  },
  killedRow: {
    display: "flex",
    gap: 12,
    padding: "8px 0",
    borderBottom: "1px solid #1a1a2a"
  },
  eventRow: {
    display: "flex",
    gap: 12,
    padding: "5px 0",
    borderBottom: "1px solid #111",
    alignItems: "center"
  },
  rowTime: {
    fontFamily: "monospace",
    fontSize: 11,
    color: "#444",
    minWidth: 60
  },
  rowMain: {
    display: "flex",
    flexDirection: "column",
    gap: 2
  },
  rowFile: {
    fontFamily: "monospace",
    fontSize: 11,
    color: "#555"
  },
  alertReason: {
    fontSize: 13,
    color: "#ff6b6b"
  },
  killedName: {
    fontSize: 13,
    color: "#ffaa00",
    fontWeight: 600
  },
  eventType: {
    fontFamily: "monospace",
    fontSize: 11,
    padding: "2px 8px",
    borderRadius: 4,
    color: "#aaa",
    minWidth: 70,
    textAlign: "center"
  },
  pill: {
    fontSize: 11,
    background: "#ff440022",
    color: "#ff6b6b",
    padding: "2px 8px",
    borderRadius: 8,
    width: "fit-content"
  }
}

export default App