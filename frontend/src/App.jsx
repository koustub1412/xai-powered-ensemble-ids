/*
import { useEffect, useState } from "react";
import axios from "axios";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loggedIn, setLoggedIn] = useState(false);
  
  // Modals State
  const [selectedLog, setSelectedLog] = useState(null);
  const [showManualInput, setShowManualInput] = useState(false);
  const [manualJson, setManualJson] = useState("");

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/stats`);
      setStats(res.data);
    } catch (error) { console.error("Waiting for backend..."); }
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setHistory(res.data);
    } catch (error) { console.error("Waiting for backend..."); }
  };

  useEffect(() => {
    fetchStats();
    fetchHistory();
    const interval = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // --- DELETE HANDLERS ---
  const deleteLog = async (e, timestamp) => {
    e.stopPropagation(); 
    if (window.confirm("Delete this log entry?")) {
      try {
        await axios.delete(`${API_BASE}/delete/${timestamp}`);
        fetchStats();
        fetchHistory();
      } catch (error) {
        alert("Failed to delete log. Ensure backend delete route is added!");
      }
    }
  };

  const clearAll = async () => {
    if (window.confirm("⚠️ ARE YOU SURE? This will wipe the entire database history.")) {
      try {
        await axios.delete(`${API_BASE}/clear-all`);
        fetchStats();
        fetchHistory();
      } catch (error) {
        alert("Failed to clear database history.");
      }
    }
  };

  const formatExactTime = (isoString) => {
    if (!isoString) return "N/A";
    const utcString = isoString.endsWith('Z') ? isoString : `${isoString}Z`;
    const date = new Date(utcString);
    if (isNaN(date.getTime())) return "Invalid Date";
    const pad = (n, digits = 2) => n.toString().padStart(digits, '0');
    return `${date.toLocaleDateString("en-GB")} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
  };

  // --- 🛠️ UPDATED 4-CLASS HIGH-STRENGTH SIMULATOR ---
  const simulateTraffic = async () => {
    const rand = Math.random();
    let sample = {};

    if (rand < 0.25) {
      // 🟢 STRONG NORMAL
      sample = {
        duration: 0,
        protocol_type: "tcp",
        service: "http",
        flag: "SF",
        src_bytes: 800,
        dst_bytes: 20000,
        logged_in: 1,
        count: 1,
        srv_count: 1,
        same_srv_rate: 1.0,
        serror_rate: 0,
        srv_serror_rate: 0,
        dst_host_serror_rate: 0,
        dst_host_srv_serror_rate: 0
      };
    } else if (rand < 0.5) {
      // 🟡 STRONG DoS
      sample = {
        duration: 0,
        protocol_type: "tcp",
        service: "http",
        flag: "S0",
        src_bytes: 0,
        dst_bytes: 0,
        count: 600,
        srv_count: 600,
        serror_rate: 1.0,
        srv_serror_rate: 1.0,
        dst_host_serror_rate: 1.0,
        dst_host_srv_serror_rate: 1.0
      };
    } else if (rand < 0.75) {
      // 🔵 STRONG PROBE
      sample = {
        duration: 0,
        protocol_type: "tcp",
        service: "ftp_data",
        flag: "REJ",
        src_bytes: 0,
        dst_bytes: 0,
        count: 40,
        srv_count: 15,
        same_srv_rate: 0.3,
        dst_host_count: 180,
        dst_host_diff_srv_rate: 0.8
      };
    } else {
      // 🔴 STRONG PRIVILEGE
      sample = {
        duration: 12,
        protocol_type: "tcp",
        service: "telnet",
        flag: "SF",
        src_bytes: 2500,
        dst_bytes: 4000,
        logged_in: 1,
        hot: 5,
        root_shell: 1,
        num_root: 3,
        num_compromised: 3,
        count: 1,
        srv_count: 1
      };
    }

    const fullPayload = {
      duration: sample.duration ?? 0,
      protocol_type: sample.protocol_type ?? "tcp",
      service: sample.service ?? "http",
      flag: sample.flag ?? "SF",
      src_bytes: sample.src_bytes ?? 0,
      dst_bytes: sample.dst_bytes ?? 0,
      land: 0,
      wrong_fragment: 0,
      urgent: 0,
      hot: sample.hot ?? 0,
      num_failed_logins: 0,
      logged_in: sample.logged_in ?? 0,
      num_compromised: sample.num_compromised ?? 0,
      root_shell: sample.root_shell ?? 0,
      su_attempted: 0,
      num_root: sample.num_root ?? 0,
      num_file_creations: 0,
      num_shells: 0,
      num_access_files: 0,
      num_outbound_cmds: 0,
      is_host_login: 0,
      is_guest_login: 0,
      count: sample.count ?? 0,
      srv_count: sample.srv_count ?? 0,
      serror_rate: sample.serror_rate ?? 0,
      srv_serror_rate: sample.srv_serror_rate ?? 0,
      rerror_rate: 0,
      srv_rerror_rate: 0,
      same_srv_rate: sample.same_srv_rate ?? 0,
      diff_srv_rate: 0,
      srv_diff_host_rate: 0,
      dst_host_count: sample.dst_host_count ?? 0,
      dst_host_srv_count: sample.dst_host_srv_count ?? 0,
      dst_host_same_srv_rate: sample.dst_host_same_srv_rate ?? 0,
      dst_host_diff_srv_rate: sample.dst_host_diff_srv_rate ?? 0,
      dst_host_same_src_port_rate: 0,
      dst_host_srv_diff_host_rate: 0,
      dst_host_serror_rate: sample.dst_host_serror_rate ?? 0,
      dst_host_srv_serror_rate: sample.dst_host_srv_serror_rate ?? 0,
      dst_host_rerror_rate: 0,
      dst_host_srv_rerror_rate: 0
    };

    try {
      await axios.post(`${API_BASE}/predict`, fullPayload);
      fetchStats();
      fetchHistory();
    } catch (error) {
      console.error("Validation Error Payload:", fullPayload);
      alert("Validation Error! Check backend.");
    }
  };
  
  const handleManualSubmit = async () => {
    try {
      const parsedData = JSON.parse(manualJson);
      await axios.post(`${API_BASE}/predict`, parsedData);
      setShowManualInput(false); setManualJson("");
      fetchStats(); fetchHistory();
    } catch (error) { alert("Invalid JSON format!"); }
  };

  if (!loggedIn) {
    return (
      <div style={loginStyle}>
        <div style={loginBoxStyle}>
          <h2 style={{ marginBottom: "20px", color: "#00ccff" }}>🔐 SOC Admin Portal</h2>
          <input type="text" placeholder="Username" style={inputStyle} defaultValue="admin_rigved" />
          <input type="password" placeholder="Password" style={inputStyle} defaultValue="********" />
          <button style={btnStyle} onClick={() => setLoggedIn(true)}>Secure Login</button>
        </div>
      </div>
    );
  }

  if (!stats) return <div style={mainStyle}><h2>📡 Connecting to Backend Server...</h2></div>;

  // Safer Pie Data Mapping
  const pieData = [
    { name: "Normal", value: stats.normal_count || 0 },
    { name: "DoS", value: stats.dos_count || 0 },
    { name: "Probe", value: stats.probe_count || 0 },
    { name: "Privilege", value: stats.privilege_count || 0 }
  ];
  const COLORS = ["#22ff88", "#ffcc00", "#00ccff", "#ff0044"];

  return (
    <div style={mainStyle}>
      {stats.critical_alerts > 0 && <div style={criticalBanner}>🚨 CRITICAL PRIVILEGE ATTACK DETECTED 🚨</div>}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", flexWrap: "wrap" }}>
        <h1>🛡️ Live Hybrid IDS SOC Dashboard</h1>
        <div style={{ display: "flex", gap: "15px" }}>
          <button style={{...btnStyle, backgroundColor: "#ef4444", color: "white"}} onClick={clearAll}>
            🗑️ Clear History
          </button>
          <button style={{...btnStyle, backgroundColor: "#3b82f6", color: "white"}} onClick={() => setShowManualInput(true)}>📥 Custom Data</button>
          <button style={btnStyle} onClick={simulateTraffic}>⚡ Inject Test Packet</button>
        </div>
      </div>

      <div style={statsContainer}>
        <StatCard title="Total Traffic" value={stats.total_packets} />
        <StatCard title="Normal" value={stats.normal_count} color="#22ff88" />
        <StatCard title="DoS Detected" value={stats.dos_count} color="#ffcc00" />
        <StatCard title="Probe Scans" value={stats.probe_count} color="#00ccff" />
        <StatCard title="Privilege" value={stats.privilege_count} color="#ff0044" />
        <StatCard title="CRITICAL Risk" value={stats.critical_alerts} color="#ff0044" />
      </div>

      <div style={middleSection}>
        <div style={cardStyle}>
          <h3 style={{ marginBottom: "15px" }}>Attack Distribution</h3>
          <PieChart width={350} height={300}>
            <Pie data={pieData} dataKey="value" innerRadius={70} outerRadius={110}>
              {pieData.map((entry, index) => <Cell key={index} fill={COLORS[index]} />)}
            </Pie>
            <Tooltip /> <Legend />
          </PieChart>
        </div>

        <div style={{ ...cardStyle, flex: 1, minWidth: "350px" }}>
          <h3 style={{ marginBottom: "15px" }}>Live Traffic Logs (Click Row for XAI Report)</h3>
          <table style={tableStyle}>
            <thead>
              <tr style={{ borderBottom: "2px solid #334155" }}>
                <th style={{ padding: "10px" }}>Timestamp</th> 
                <th style={{ padding: "10px" }}>Prediction</th> 
                <th style={{ padding: "10px" }}>Risk</th>
                <th style={{ padding: "10px" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map((log, index) => (
                <tr key={index} style={rowStyle} onClick={() => setSelectedLog(log)}>
                  <td style={{ padding: "12px 10px", color: "#94a3b8" }}>{formatExactTime(log.timestamp)}</td>
                  <td style={{ padding: "12px 10px", fontWeight: "bold" }}>{log.prediction}</td>
                  <td style={{ 
                    padding: "12px 10px", 
                    fontWeight: "bold", 
                    color: log.risk_level === "CRITICAL" ? "#ff0044" : 
                           log.risk_level === "HIGH" ? "#ffcc00" : 
                           log.risk_level === "MEDIUM" ? "#fb923c" : "#22ff88" 
                  }}>
                    {log.risk_level}
                  </td>
                  <td style={{ padding: "12px 10px" }}>
                    <button 
                        style={deleteBtnStyle} 
                        onClick={(e) => deleteLog(e, log.timestamp)}
                        title="Delete log"
                    >
                        🗑️
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      //{ 🧠 SHAP EXPLAINABILITY MODAL WITH UPDATED RISK COLORS }
      {selectedLog && (
        <div style={modalOverlay}>
          <div style={{ ...modalContent, width: "700px", textAlign: "left", maxHeight: "85vh", overflowY: "auto" }}>
            <h2 style={{ color: "#00ccff", borderBottom: "1px solid #334155", paddingBottom: "10px" }}>🛡️ AUTOMATED CYBER-ANALYST REPORT</h2>
            <div style={{ marginTop: "15px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                <p><strong>📡 Packet ID:</strong> {selectedLog._id ? selectedLog._id.substring(18) : "N/A"}</p>
                <p><strong>🕒 Time:</strong> {formatExactTime(selectedLog.timestamp)}</p>
                <p><strong>🤖 AI Prediction:</strong> <span style={{color: "#00ccff"}}>{selectedLog.prediction}</span></p>
                <p><strong>⚠️ Risk Level:</strong> 
                  <span style={{ 
                    marginLeft: "8px",
                    fontWeight: "bold",
                    color:
                      selectedLog.risk_level === "CRITICAL" ? "#ff0044" :
                      selectedLog.risk_level === "HIGH" ? "#ffcc00" :
                      selectedLog.risk_level === "MEDIUM" ? "#fb923c" :
                      "#22ff88"
                  }}>
                    {selectedLog.risk_level}
                  </span>
                </p>
            </div>
            
            <div style={{ backgroundColor: "#0f172a", padding: "20px", borderRadius: "8px", marginTop: "20px", border: "1px solid #00ccff" }}>
              <h4 style={{ color: "#00ccff", marginBottom: "10px" }}>🔍 FORENSIC BREAKDOWN (XAI)</h4>
              <pre style={{ 
                whiteSpace: "pre-wrap", 
                fontFamily: "'Courier New', monospace", 
                fontSize: "14px", 
                color: "#e2e8f0", 
                lineHeight: "1.4" 
              }}>
                {selectedLog.explanation}
              </pre>
            </div>
            <button style={{...btnStyle, width: "100%", marginTop: "20px"}} onClick={() => setSelectedLog(null)}>Acknowledge & Close</button>
          </div>
        </div>
      )}

      //{ MANUAL INPUT MODAL }
      {showManualInput && (
        <div style={modalOverlay}>
          <div style={modalContent}>
            <h3 style={{ color: "#00ccff", marginBottom: "15px" }}>📥 Manual Data Injection</h3>
            <textarea style={textAreaStyle} placeholder='Paste JSON here...' value={manualJson} onChange={(e) => setManualJson(e.target.value)} />
            <div style={{ display: "flex", gap: "10px", marginTop: "15px" }}>
              <button style={btnStyle} onClick={handleManualSubmit}>Analyze Packet</button>
              <button style={{...btnStyle, backgroundColor: "#334155", color: "white"}} onClick={() => setShowManualInput(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// STYLES
const mainStyle = { padding: "40px", backgroundColor: "#0f172a", minHeight: "100vh", width: "100%", color: "white", fontFamily: "system-ui" };
const loginStyle = { minHeight: "100vh", width: "100%", display: "flex", justifyContent: "center", alignItems: "center", backgroundColor: "#0f172a" };
const loginBoxStyle = { backgroundColor: "#1e293b", padding: "50px", borderRadius: "12px", boxShadow: "0 0 30px rgba(0, 204, 255, 0.2)", width: "400px", textAlign: "center" };
const inputStyle = { padding: "12px", marginBottom: "15px", borderRadius: "6px", border: "1px solid #334155", backgroundColor: "#0f172a", color: "white", width: "100%" };
const btnStyle = { padding: "12px 20px", backgroundColor: "#00ccff", border: "none", borderRadius: "6px", color: "black", fontWeight: "bold", cursor: "pointer" };
const criticalBanner = { backgroundColor: "#ff0044", padding: "15px", textAlign: "center", fontWeight: "bold", marginBottom: "30px", borderRadius: "8px", animation: "pulse 1.5s infinite" };
const statsContainer = { display: "flex", gap: "20px", marginBottom: "40px", flexWrap: "wrap" };
const middleSection = { display: "flex", gap: "40px", alignItems: "flex-start", flexWrap: "wrap" };
const cardStyle = { backgroundColor: "#1e293b", padding: "25px", borderRadius: "12px", border: "1px solid #334155" };
const tableStyle = { width: "100%", borderCollapse: "collapse", textAlign: "left" };
const rowStyle = { borderBottom: "1px solid #1e293b", cursor: "pointer" };
const modalOverlay = { position: "fixed", top: 0, left: 0, width: "100%", height: "100%", backgroundColor: "rgba(0,0,0,0.85)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 };
const modalContent = { backgroundColor: "#1e293b", padding: "30px", borderRadius: "12px", border: "1px solid #00ccff" };
const textAreaStyle = { width: "100%", height: "200px", backgroundColor: "#0f172a", color: "#22ff88", padding: "10px", borderRadius: "8px", fontFamily: "monospace" };

const deleteBtnStyle = {
  background: "none",
  border: "none",
  cursor: "pointer",
  fontSize: "18px",
  padding: "5px",
  borderRadius: "4px",
  transition: "background 0.2s",
};

function StatCard({ title, value, color="white" }) {
  return (
    <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "10px", flex: 1, minWidth: "160px", border: "1px solid #334155" }}>
      <h4 style={{ opacity: 0.7, fontSize: "12px", marginBottom: "8px" }}>{title}</h4>
      <h2 style={{ color, fontSize: "32px", margin: 0 }}>{value}</h2>
    </div>
  );
}

export default App;

*/

/*
import { useEffect, useState } from "react";
import axios from "axios";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loggedIn, setLoggedIn] = useState(false);
  
  // Modals & Selection State
  const [selectedLog, setSelectedLog] = useState(null);
  const [showManualInput, setShowManualInput] = useState(false);
  const [manualJson, setManualJson] = useState("");
  
  // 🟢 NEW: State to track which ML Model to use
  const [datasetType, setDatasetType] = useState("nsl");

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/stats`);
      setStats(res.data);
    } catch (error) { console.error("Waiting for backend..."); }
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setHistory(res.data);
    } catch (error) { console.error("Waiting for backend..."); }
  };

  useEffect(() => {
    fetchStats();
    fetchHistory();
    const interval = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // --- DELETE HANDLERS ---
  const deleteLog = async (e, timestamp) => {
    e.stopPropagation(); 
    if (window.confirm("Delete this log entry?")) {
      try {
        await axios.delete(`${API_BASE}/delete/${timestamp}`);
        fetchStats();
        fetchHistory();
      } catch (error) {
        alert("Failed to delete log. Ensure backend delete route is added!");
      }
    }
  };

  const clearAll = async () => {
    if (window.confirm("⚠️ ARE YOU SURE? This will wipe the entire database history.")) {
      try {
        await axios.delete(`${API_BASE}/clear-all`);
        fetchStats();
        fetchHistory();
      } catch (error) {
        alert("Failed to clear database history.");
      }
    }
  };

  const formatExactTime = (isoString) => {
    if (!isoString) return "N/A";
    const utcString = isoString.endsWith('Z') ? isoString : `${isoString}Z`;
    const date = new Date(utcString);
    if (isNaN(date.getTime())) return "Invalid Date";
    const pad = (n, digits = 2) => n.toString().padStart(digits, '0');
    return `${date.toLocaleDateString("en-GB")} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
  };

  // --- 🛠️ UPDATED SIMULATOR ---
  const simulateTraffic = async () => {
    const rand = Math.random();
    let sample = {};

    if (rand < 0.25) {
      sample = { duration: 0, protocol_type: "tcp", service: "http", flag: "SF", src_bytes: 800, dst_bytes: 20000, logged_in: 1, count: 1, srv_count: 1, same_srv_rate: 1.0, serror_rate: 0, srv_serror_rate: 0, dst_host_serror_rate: 0, dst_host_srv_serror_rate: 0 };
    } else if (rand < 0.5) {
      sample = { duration: 0, protocol_type: "tcp", service: "http", flag: "S0", src_bytes: 0, dst_bytes: 0, count: 600, srv_count: 600, serror_rate: 1.0, srv_serror_rate: 1.0, dst_host_serror_rate: 1.0, dst_host_srv_serror_rate: 1.0 };
    } else if (rand < 0.75) {
      sample = { duration: 0, protocol_type: "tcp", service: "ftp_data", flag: "REJ", src_bytes: 0, dst_bytes: 0, count: 40, srv_count: 15, same_srv_rate: 0.3, dst_host_count: 180, dst_host_diff_srv_rate: 0.8 };
    } else {
      sample = { duration: 12, protocol_type: "tcp", service: "telnet", flag: "SF", src_bytes: 2500, dst_bytes: 4000, logged_in: 1, hot: 5, root_shell: 1, num_root: 3, num_compromised: 3, count: 1, srv_count: 1 };
    }

    const fullPayload = {
      dataset_type: datasetType, // 🟢 NEW: Attach dropdown choice
      duration: sample.duration ?? 0,
      protocol_type: sample.protocol_type ?? "tcp",
      service: sample.service ?? "http",
      flag: sample.flag ?? "SF",
      src_bytes: sample.src_bytes ?? 0,
      dst_bytes: sample.dst_bytes ?? 0,
      land: 0,
      wrong_fragment: 0,
      urgent: 0,
      hot: sample.hot ?? 0,
      num_failed_logins: 0,
      logged_in: sample.logged_in ?? 0,
      num_compromised: sample.num_compromised ?? 0,
      root_shell: sample.root_shell ?? 0,
      su_attempted: 0,
      num_root: sample.num_root ?? 0,
      num_file_creations: 0,
      num_shells: 0,
      num_access_files: 0,
      num_outbound_cmds: 0,
      is_host_login: 0,
      is_guest_login: 0,
      count: sample.count ?? 0,
      srv_count: sample.srv_count ?? 0,
      serror_rate: sample.serror_rate ?? 0,
      srv_serror_rate: sample.srv_serror_rate ?? 0,
      rerror_rate: 0,
      srv_rerror_rate: 0,
      same_srv_rate: sample.same_srv_rate ?? 0,
      diff_srv_rate: 0,
      srv_diff_host_rate: 0,
      dst_host_count: sample.dst_host_count ?? 0,
      dst_host_srv_count: sample.dst_host_srv_count ?? 0,
      dst_host_same_srv_rate: sample.dst_host_same_srv_rate ?? 0,
      dst_host_diff_srv_rate: sample.dst_host_diff_srv_rate ?? 0,
      dst_host_same_src_port_rate: 0,
      dst_host_srv_diff_host_rate: 0,
      dst_host_serror_rate: sample.dst_host_serror_rate ?? 0,
      dst_host_srv_serror_rate: sample.dst_host_srv_serror_rate ?? 0,
      dst_host_rerror_rate: 0,
      dst_host_srv_rerror_rate: 0
    };

    try {
      await axios.post(`${API_BASE}/predict`, fullPayload);
      fetchStats();
      fetchHistory();
    } catch (error) {
      console.error("Validation Error Payload:", fullPayload);
      alert("Validation Error! Check backend.");
    }
  };
  
  const handleManualSubmit = async () => {
    try {
      const parsedData = JSON.parse(manualJson);
      parsedData.dataset_type = datasetType; // 🟢 NEW: Attach dropdown choice to manual JSON
      
      await axios.post(`${API_BASE}/predict`, parsedData);
      setShowManualInput(false); setManualJson("");
      fetchStats(); fetchHistory();
    } catch (error) { alert("Invalid JSON format!"); }
  };

  if (!loggedIn) {
    return (
      <div style={loginStyle}>
        <div style={loginBoxStyle}>
          <h2 style={{ marginBottom: "20px", color: "#00ccff" }}>🔐 SOC Admin Portal</h2>
          <input type="text" placeholder="Username" style={inputStyle} defaultValue="admin_rigved" />
          <input type="password" placeholder="Password" style={inputStyle} defaultValue="********" />
          <button style={btnStyle} onClick={() => setLoggedIn(true)}>Secure Login</button>
        </div>
      </div>
    );
  }

  if (!stats) return <div style={mainStyle}><h2>📡 Connecting to Backend Server...</h2></div>;

  // Dynamic Pie Data Mapping
  const pieData = stats.chart_data && stats.chart_data.length > 0 
    ? stats.chart_data 
    : [{ name: "No Traffic", value: 1 }];

  // Expanded color palette for various attack types
  const COLORS = ["#ff0044", "#00ccff", "#fb923c", "#22ff88", "#ffcc00", "#a855f7"];

  return (
    <div style={mainStyle}>
      {stats.critical_alerts > 0 && <div style={criticalBanner}>🚨 CRITICAL PRIVILEGE ATTACK DETECTED 🚨</div>}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", flexWrap: "wrap" }}>
        <h1>🛡️ Live Hybrid IDS SOC Dashboard</h1>
        <div style={{ display: "flex", gap: "15px", alignItems: "center" }}>
          
          //{ 🟢 NEW: Styled Dropdown Menu }
          <select 
            value={datasetType} 
            onChange={(e) => setDatasetType(e.target.value)} 
            style={selectStyle}
          >
            <option value="nsl">Legacy IT (NSL-KDD)</option>
            <option value="ton">IoT Sensors (ToN-IoT)</option>
            <option value="bot">Smart Home (BoT-IoT)</option>
          </select>

          <button style={{...btnStyle, backgroundColor: "#ef4444", color: "white"}} onClick={clearAll}>
            🗑️ Clear History
          </button>
          <button style={{...btnStyle, backgroundColor: "#3b82f6", color: "white"}} onClick={() => setShowManualInput(true)}>📥 Custom Data</button>
          <button style={btnStyle} onClick={simulateTraffic}>⚡ Inject Test Packet</button>
        </div>
      </div>

      <div style={statsContainer}>
        <StatCard title="Total Traffic" value={stats.total_packets} />
        <StatCard title="Low Risk" value={stats.low_risk} color="#22ff88" />
        <StatCard title="Medium Risk" value={stats.medium_risk} color="#fb923c" />
        <StatCard title="High Risk" value={stats.high_risk} color="#ffcc00" />
        <StatCard title="CRITICAL Alerts" value={stats.critical_alerts} color="#ff0044" />
      </div>

      <div style={middleSection}>
        <div style={cardStyle}>
          <h3 style={{ marginBottom: "15px" }}>Attack Distribution</h3>
          <PieChart width={350} height={300}>
            <Pie data={pieData} dataKey="value" innerRadius={70} outerRadius={110}>
              {pieData.map((entry, index) => <Cell key={index} fill={COLORS[index]} />)}
            </Pie>
            <Tooltip /> <Legend />
          </PieChart>
        </div>

        <div style={{ ...cardStyle, flex: 1, minWidth: "350px" }}>
          <h3 style={{ marginBottom: "15px" }}>Live Traffic Logs (Click Row for XAI Report)</h3>
          <table style={tableStyle}>
            <thead>
              <tr style={{ borderBottom: "2px solid #334155" }}>
                <th style={{ padding: "10px" }}>Timestamp</th> 
                <th style={{ padding: "10px" }}>Prediction</th> 
                <th style={{ padding: "10px" }}>Risk</th>
                <th style={{ padding: "10px" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {history.map((log, index) => (
                <tr key={index} style={rowStyle} onClick={() => setSelectedLog(log)}>
                  <td style={{ padding: "12px 10px", color: "#94a3b8" }}>{formatExactTime(log.timestamp)}</td>
                  <td style={{ padding: "12px 10px", fontWeight: "bold" }}>{log.prediction}</td>
                  <td style={{ 
                    padding: "12px 10px", 
                    fontWeight: "bold", 
                    color: log.risk_level === "CRITICAL" ? "#ff0044" : 
                           log.risk_level === "HIGH" ? "#ffcc00" : 
                           log.risk_level === "MEDIUM" ? "#fb923c" : "#22ff88" 
                  }}>
                    {log.risk_level}
                  </td>
                  <td style={{ padding: "12px 10px" }}>
                    <button 
                        style={deleteBtnStyle} 
                        onClick={(e) => deleteLog(e, log.timestamp)}
                        title="Delete log"
                    >
                        🗑️
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      //{ 🧠 SHAP EXPLAINABILITY MODAL }
      {selectedLog && (
        <div style={modalOverlay}>
          <div style={{ ...modalContent, width: "700px", textAlign: "left", maxHeight: "85vh", overflowY: "auto" }}>
            <h2 style={{ color: "#00ccff", borderBottom: "1px solid #334155", paddingBottom: "10px" }}>🛡️ AUTOMATED CYBER-ANALYST REPORT</h2>
            <div style={{ marginTop: "15px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                <p><strong>📡 Packet ID:</strong> {selectedLog._id ? selectedLog._id.substring(18) : "N/A"}</p>
                <p><strong>🕒 Time:</strong> {formatExactTime(selectedLog.timestamp)}</p>
                <p><strong>🤖 AI Prediction:</strong> <span style={{color: "#00ccff"}}>{selectedLog.prediction}</span></p>
                <p><strong>⚠️ Risk Level:</strong> 
                  <span style={{ 
                    marginLeft: "8px",
                    fontWeight: "bold",
                    color:
                      selectedLog.risk_level === "CRITICAL" ? "#ff0044" :
                      selectedLog.risk_level === "HIGH" ? "#ffcc00" :
                      selectedLog.risk_level === "MEDIUM" ? "#fb923c" :
                      "#22ff88"
                  }}>
                    {selectedLog.risk_level}
                  </span>
                </p>
            </div>
            
            <div style={{ backgroundColor: "#0f172a", padding: "20px", borderRadius: "8px", marginTop: "20px", border: "1px solid #00ccff" }}>
              <h4 style={{ color: "#00ccff", marginBottom: "10px" }}>🔍 FORENSIC BREAKDOWN (XAI)</h4>
              <pre style={{ 
                whiteSpace: "pre-wrap", 
                fontFamily: "'Courier New', monospace", 
                fontSize: "14px", 
                color: "#e2e8f0", 
                lineHeight: "1.4" 
              }}>
                {selectedLog.explanation}
              </pre>
            </div>
            <button style={{...btnStyle, width: "100%", marginTop: "20px"}} onClick={() => setSelectedLog(null)}>Acknowledge & Close</button>
          </div>
        </div>
      )}

      //{ MANUAL INPUT MODAL }
      {showManualInput && (
        <div style={modalOverlay}>
          <div style={modalContent}>
            <h3 style={{ color: "#00ccff", marginBottom: "15px" }}>📥 Manual Data Injection</h3>
            <textarea style={textAreaStyle} placeholder='Paste JSON here...' value={manualJson} onChange={(e) => setManualJson(e.target.value)} />
            <div style={{ display: "flex", gap: "10px", marginTop: "15px" }}>
              <button style={btnStyle} onClick={handleManualSubmit}>Analyze Packet</button>
              <button style={{...btnStyle, backgroundColor: "#334155", color: "white"}} onClick={() => setShowManualInput(false)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// STYLES
const mainStyle = { padding: "40px", backgroundColor: "#0f172a", minHeight: "100vh", width: "100%", color: "white", fontFamily: "system-ui" };
const loginStyle = { minHeight: "100vh", width: "100%", display: "flex", justifyContent: "center", alignItems: "center", backgroundColor: "#0f172a" };
const loginBoxStyle = { backgroundColor: "#1e293b", padding: "50px", borderRadius: "12px", boxShadow: "0 0 30px rgba(0, 204, 255, 0.2)", width: "400px", textAlign: "center" };
const inputStyle = { padding: "12px", marginBottom: "15px", borderRadius: "6px", border: "1px solid #334155", backgroundColor: "#0f172a", color: "white", width: "100%" };
const btnStyle = { padding: "12px 20px", backgroundColor: "#00ccff", border: "none", borderRadius: "6px", color: "black", fontWeight: "bold", cursor: "pointer" };

// 🟢 NEW: Style for the dropdown menu
const selectStyle = { padding: "12px", backgroundColor: "#1e293b", color: "#00ccff", border: "1px solid #334155", borderRadius: "6px", fontWeight: "bold", cursor: "pointer", outline: "none" };

const criticalBanner = { backgroundColor: "#ff0044", padding: "15px", textAlign: "center", fontWeight: "bold", marginBottom: "30px", borderRadius: "8px", animation: "pulse 1.5s infinite" };
const statsContainer = { display: "flex", gap: "20px", marginBottom: "40px", flexWrap: "wrap" };
const middleSection = { display: "flex", gap: "40px", alignItems: "flex-start", flexWrap: "wrap" };
const cardStyle = { backgroundColor: "#1e293b", padding: "25px", borderRadius: "12px", border: "1px solid #334155" };
const tableStyle = { width: "100%", borderCollapse: "collapse", textAlign: "left" };
const rowStyle = { borderBottom: "1px solid #1e293b", cursor: "pointer" };
const modalOverlay = { position: "fixed", top: 0, left: 0, width: "100%", height: "100%", backgroundColor: "rgba(0,0,0,0.85)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 };
const modalContent = { backgroundColor: "#1e293b", padding: "30px", borderRadius: "12px", border: "1px solid #00ccff" };
const textAreaStyle = { width: "100%", height: "200px", backgroundColor: "#0f172a", color: "#22ff88", padding: "10px", borderRadius: "8px", fontFamily: "monospace" };

const deleteBtnStyle = { background: "none", border: "none", cursor: "pointer", fontSize: "18px", padding: "5px", borderRadius: "4px", transition: "background 0.2s" };

function StatCard({ title, value, color="white" }) {
  return (
    <div style={{ backgroundColor: "#1e293b", padding: "20px", borderRadius: "10px", flex: 1, minWidth: "160px", border: "1px solid #334155" }}>
      <h4 style={{ opacity: 0.7, fontSize: "12px", marginBottom: "8px" }}>{title}</h4>
      <h2 style={{ color, fontSize: "32px", margin: 0 }}>{value}</h2>
    </div>
  );
}

export default App;
*/

import { useEffect, useState } from "react";
import axios from "axios";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loggedIn, setLoggedIn] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const [showManualInput, setShowManualInput] = useState(false);
  const [manualJson, setManualJson] = useState("");
  const [datasetType, setDatasetType] = useState("nsl");

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/stats`);
      setStats(res.data);
    } catch {}
  };

  const fetchHistory = async () => {
    try {
      const res = await axios.get(`${API_BASE}/history`);
      setHistory(res.data);
    } catch {}
  };

  useEffect(() => {
    fetchStats();
    fetchHistory();
    const interval = setInterval(() => {
      fetchStats();
      fetchHistory();
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const deleteLog = async (e, timestamp) => {
    e.stopPropagation();
    await axios.delete(`${API_BASE}/delete/${timestamp}`);
    fetchStats();
    fetchHistory();
  };

  const clearAll = async () => {
    await axios.delete(`${API_BASE}/clear-all`);
    fetchStats();
    fetchHistory();
  };

  const handleCSVUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      await axios.post(`${API_BASE}/predict-file/${datasetType}`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      fetchStats();
      fetchHistory();
      alert("CSV Uploaded Successfully!");
    } catch {
      alert("CSV Upload Failed!");
    }
  };
  const simulateTraffic = async () => {
    let sample = {};
    const rand = Math.random();

    // 1. Logic for NSL-KDD (Legacy IT)
    if (datasetType === "nsl") {
      if (rand < 0.25) {
        sample = { duration: 0, protocol_type: "tcp", service: "http", flag: "SF", src_bytes: 800, dst_bytes: 20000, logged_in: 1, count: 1 };
      } else if (rand < 0.5) {
        sample = { duration: 0, protocol_type: "tcp", service: "http", flag: "S0", src_bytes: 0, dst_bytes: 0, count: 600, srv_count: 600 };
      } else if (rand < 0.75) {
        sample = { duration: 0, protocol_type: "tcp", service: "ftp_data", flag: "REJ", src_bytes: 0, dst_bytes: 0, count: 40, srv_count: 15 };
      } else {
        sample = { duration: 12, protocol_type: "tcp", service: "telnet", flag: "SF", src_bytes: 2500, dst_bytes: 4000, logged_in: 1, hot: 5, root_shell: 1 };
      }
    } 
    
    
    
  else if (datasetType === "ton") {

  // 🔹 Base Template (common realistic flow structure)
  const baseTon = {
    duration: 5,
    src_bytes: 100,
    dst_bytes: 100,
    missed_bytes: 0,
    src_pkts: 5,
    dst_pkts: 5,
    src_ip_bytes: 200,
    dst_ip_bytes: 200,
    dns_qclass: 1,
    dns_qtype: 1,
    dns_rcode: 0,
    proto: "tcp",
    conn_state: "SF",
    dns_query: "-",
    dns_AA: "F",
    dns_RD: "T",
    dns_RA: "T",
    dns_rejected: "F",
    ssl_version: "TLSv12",
    ssl_established: "-",
    http_uri: "-",
    weird_name: "active_connection_reuse"
  };

  // 🔹 Attack Templates (only override what matters)
  const tonTemplates = {

    normal: {
      ...baseTon
    },

    mitm: {
      ...baseTon,
      proto: "udp",
      dns_AA: "T",
      dns_RA: "F",
      dns_query: "broker.hivemq.com"
    },

    ddos: {
      ...baseTon,
      duration: 60,
      src_pkts: 50000,
      dst_pkts: 50000,
      conn_state: "S0",
      dns_rejected: "T"
    },

    dos: {
      ...baseTon,
      duration: 40,
      src_pkts: 20000,
      dst_pkts: 500,
      conn_state: "S0"
    },

    scanning: {
      ...baseTon,
      duration: 0.001,
      src_pkts: 3000,
      dst_pkts: 10,
      conn_state: "REJ"
    },

    injection: {
      ...baseTon,
      dns_query: "testphp.vulnweb.com/listproducts.php",
      dns_AA: "T",
      dns_RA: "F"
    },

    xss: {
      ...baseTon,
      dns_query: "www.dvwa.co.uk",
      duration: 3,
      src_bytes: 800
    },

    password: {
      ...baseTon,
      duration: 8,
      src_pkts: 50,
      dst_pkts: 50,
      dns_query: "192.168.1.195/dvwa/login.php-r"
    },

    ransomware: {
      ...baseTon,
      duration: 25,
      src_bytes: 50000,
      dst_bytes: 100,
      dns_query: "elasticsearch.mydns.com"
    },

    backdoor: {
      ...baseTon,
      duration: 15,
      proto: "udp",
      conn_state: "OTH",
      dns_query: "hnzwefg.mydns.com"
    }
  };

  // 🔹 Randomly choose one of the 10 attack types
  const attackTypes = Object.keys(tonTemplates);
  const chosen =
    attackTypes[Math.floor(Math.random() * attackTypes.length)];

  sample = tonTemplates[chosen];

  console.log("🚀 TON Injecting:", chosen);
}
    
    // 🚀 HIGH-CONTRAST BoT-IoT Simulation (To break DDoS/Recon bias)
    else if (datasetType === "bot") {
      if (rand < 0.60) {
        // NORMAL (60%): High duration, low rate, established connection
        sample = { 
          bytes: 5000, pkts: 10, dur: 20.0, 
          rate: 0.5, srate: 0.2, drate: 0.3, 
          state: "CON", proto: "tcp" 
        };
      } 
      else if (rand < 0.75) {
        // RECONNAISSANCE (15%): Micro-duration, high source rate, reset state
        sample = { 
          bytes: 40, pkts: 20, dur: 0.001, 
          rate: 5000, srate: 5000, drate: 0, 
          state: "RST", proto: "tcp" 
        };
      } 
      else if (rand < 0.90) {
        // DoS (15%): Large packet count, moderate rate, requested state
        sample = { 
          bytes: 8000, pkts: 1200, dur: 15.0, 
          rate: 80, srate: 80, drate: 0, 
          state: "REQ", proto: "tcp" 
        };
      } 
      else {
        // DDoS (10%): Massive flood, tiny duration, UDP protocol
        sample = { 
          bytes: 100, pkts: 2000, dur: 0.1, 
          rate: 15000, srate: 15000, drate: 0, 
          state: "INT", proto: "udp" 
        };
      }
    }

  const payload = { ...sample, dataset_type: datasetType };

  try {
    await axios.post(`${API_BASE}/predict`, payload);
    fetchStats();
    fetchHistory();
  } catch {
    alert("Injection failed!");
  }
};
  const formatExactTime = (isoString) => {
    if (!isoString) return "N/A";
    const utcString = isoString.endsWith("Z") ? isoString : `${isoString}Z`;
    const date = new Date(utcString);
    if (isNaN(date.getTime())) return "Invalid Date";
    const pad = (n, digits = 2) => n.toString().padStart(digits, "0");
    return `${date.toLocaleDateString("en-GB")} ${pad(date.getHours())}:${pad(
      date.getMinutes()
    )}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
  };

  if (!loggedIn) {
    return (
      <div style={loginStyle}>
        <div style={loginBoxStyle}>
          <h2 style={{ marginBottom: "20px", color: "#00ccff" }}>🔐 SOC Admin Portal</h2>
          <button style={btnStyle} onClick={() => setLoggedIn(true)}>Secure Login</button>
        </div>
      </div>
    );
  }

  if (!stats) return <div style={mainStyle}><h2>Connecting...</h2></div>;

  const COLORS = ["#ff0044", "#00ccff", "#fb923c", "#22ff88", "#ffcc00"];

  return (
  <div style={mainStyle}>
    
    {/* ================= HEADER ROW ================= */}
    <div
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "30px",
        flexWrap: "wrap",
        gap: "20px"
      }}
    >
      {/* LEFT → APP NAME */}
      <h1 style={{ margin: 0 }}>
        🛡️ Live Hybrid IDS SOC Dashboard
      </h1>

      {/* RIGHT → CONTROLS */}
      <div
        style={{
          display: "flex",
          gap: "12px",
          alignItems: "center",
          flexWrap: "wrap"
        }}
      >
        <select
          value={datasetType}
          onChange={(e) => setDatasetType(e.target.value)}
          style={selectStyle}
        >
          <option value="nsl">Legacy IT (NSL-KDD)</option>
          <option value="ton">IoT Sensors (ToN-IoT)</option>
          <option value="bot">Smart Home (BoT-IoT)</option>
        </select>

        <label style={btnStyle}>
          📂 Upload CSV
          <input
            type="file"
            accept=".csv"
            style={{ display: "none" }}
            onChange={handleCSVUpload}
          />
        </label>

        <button style={btnStyle} onClick={simulateTraffic}>
          ⚡ Inject
        </button>

        <button
          style={{ ...btnStyle, backgroundColor: "#ef4444", color: "white" }}
          onClick={clearAll}
        >
          🗑 Clear
        </button>
      </div>
    </div>

    {/* ================= STATS ROW (FULL WIDTH) ================= */}
    <div
      style={{
        display: "flex",
        gap: "20px",
        marginBottom: "40px",
        flexWrap: "wrap",
        justifyContent: "space-between"
      }}
    >
      <StatCard title="Total Traffic" value={stats.total_packets} />
      <StatCard title="Low Risk" value={stats.low_risk} color="#22ff88" />
      <StatCard title="Medium Risk" value={stats.medium_risk} color="#fb923c" />
      <StatCard title="High Risk" value={stats.high_risk} color="#ffcc00" />
      <StatCard
        title="CRITICAL Alerts"
        value={stats.critical_alerts}
        color="#ff0044"
      />
    </div>

    {/* ================= MAIN CONTENT ================= */}
    <div style={middleSection}>
      
      {/* LEFT - PIE CHART */}
      <div style={cardStyle}>
        <h3 style={{ marginBottom: "15px" }}>Attack Distribution</h3>

        <PieChart width={350} height={300}>
          <Pie
            data={
              stats.chart_data && stats.chart_data.length > 0
                ? stats.chart_data
                : [{ name: "No Traffic", value: 1 }]
            }
            dataKey="value"
            innerRadius={70}
            outerRadius={110}
          >
            {(stats.chart_data || []).map((entry, index) => (
              <Cell key={index} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </div>

      {/* RIGHT - TABLE */}
      <div style={{ ...cardStyle, flex: 1, minWidth: "350px" }}>
        <h3 style={{ marginBottom: "15px" }}>
          Live Traffic Logs (Click Row for XAI Report)
        </h3>

        <table style={tableStyle}>
          <thead>
            <tr style={{ borderBottom: "2px solid #334155" }}>
              <th style={{ padding: "10px" }}>Timestamp</th>
              <th style={{ padding: "10px" }}>Environment</th>
              <th style={{ padding: "10px" }}>Prediction</th>
              <th style={{ padding: "10px" }}>Confidence</th>
              <th style={{ padding: "10px" }}>Risk</th>
              <th style={{ padding: "10px" }}>Action</th>
            </tr>
          </thead>

          <tbody>
            {history.map((log, index) => (
              <tr
                key={index}
                style={rowStyle}
                onClick={() => setSelectedLog(log)}
              >
                <td style={{ padding: "12px 10px", color: "#94a3b8" }}>
                  {formatExactTime(log.timestamp)}
                </td>

                <td
                  style={{
                    padding: "12px 10px",
                    fontWeight: "bold",
                    color: "#a855f7"
                  }}
                >
                  {
                      log.dataset === "nsl" ? "Legacy IT(NSL-KDD)" :
                      log.dataset === "ton" ? "IoT Sensors(ToN-IoT)" :
                      log.dataset === "bot" ? "Smart Home(BoT-IoT)" :
                      log.dataset || "Unknown"
                    }
                </td>

                <td style={{ padding: "12px 10px", fontWeight: "bold" }}>
                  {log.prediction}
                </td>

                <td
                  style={{
                    padding: "12px 10px",
                    color: "#00ccff",
                    fontWeight: "bold"
                  }}
                >
                  {log.confidence !== undefined
                    ? `${(log.confidence * 100).toFixed(2)}%`
                    : "N/A"}
                </td>

                <td
                  style={{
                    padding: "12px 10px",
                    fontWeight: "bold",
                    color:
                      log.risk_level === "CRITICAL"
                        ? "#ff0044"
                        : log.risk_level === "HIGH"
                        ? "#ffcc00"
                        : log.risk_level === "MEDIUM"
                        ? "#fb923c"
                        : "#22ff88"
                  }}
                >
                  {log.risk_level}
                </td>

                <td style={{ padding: "12px 10px" }}>
                  <button
                    style={deleteBtnStyle}
                    onClick={(e) => deleteLog(e, log.timestamp)}
                  >
                    🗑️
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
    {selectedLog && (
  <div style={modalOverlay}>
    <div
      style={{
        ...modalContent,
        width: "700px",
        maxHeight: "85vh",
        overflowY: "auto"
      }}
    >
      <h2 style={{ color: "#00ccff", marginBottom: "15px" }}>
        🛡️ AUTOMATED CYBER-ANALYST REPORT
      </h2>

      <div
  style={{
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "15px",
    marginBottom: "20px"
  }}
>
  {/* ENVIRONMENT */}
  <InfoCard
    label="Environment"
    value={
      selectedLog.dataset === "nsl"
        ? "Legacy IT (NSL-KDD)"
        : selectedLog.dataset === "ton"
        ? "IoT Sensors (ToN-IoT)"
        : selectedLog.dataset === "bot"
        ? "Smart Home (BoT-IoT)"
        : selectedLog.dataset
    }
  />

  {/* PREDICTION */}
  <InfoCard
    label="Prediction"
    value={selectedLog.prediction}
    highlight="#00ccff"
  />

  {/* CONFIDENCE */}
  <InfoCard
    label="Confidence"
    value={
      selectedLog.confidence !== undefined
        ? `${(selectedLog.confidence * 100).toFixed(2)}%`
        : "N/A"
    }
    highlight="#22ff88"
  />

  {/* RISK */}
  <InfoCard
    label="Risk Level"
    value={selectedLog.risk_level}
    highlight={
      selectedLog.risk_level === "CRITICAL"
        ? "#ff0044"
        : selectedLog.risk_level === "HIGH"
        ? "#ffcc00"
        : selectedLog.risk_level === "MEDIUM"
        ? "#fb923c"
        : "#22ff88"
    }
  />
</div>

      <div
        style={{
          backgroundColor: "#0f172a",
          padding: "20px",
          borderRadius: "10px",
          border: "1px solid #00ccff"
        }}
      >
        <pre
          style={{
            whiteSpace: "pre-wrap",
            fontFamily: "monospace",
            fontSize: "14px",
            color: "#e2e8f0",
            lineHeight: "1.5"
          }}
        >
          {selectedLog.explanation}
        </pre>
      </div>

      <button
        style={{ ...btnStyle, marginTop: "20px", width: "100%" }}
        onClick={() => setSelectedLog(null)}
      >
        Close
      </button>
    </div>
  </div>
)}
  </div>
);
}

// STYLES (same as yours)
/* =========================
   🎨 CLEAN PROFESSIONAL STYLING
========================= */

const mainStyle = {
  padding: "40px",
  backgroundColor: "#0b1220",
  minHeight: "100vh",
  width: "100%",
  color: "white",
  fontFamily: "system-ui",
};

const loginStyle = {
  minHeight: "100vh",
  width: "100%",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  backgroundColor: "#0b1220",
};

const loginBoxStyle = {
  backgroundColor: "#111827",
  padding: "50px",
  borderRadius: "14px",
  boxShadow: "0 0 40px rgba(0, 204, 255, 0.15)",
  width: "420px",
  textAlign: "center",
};

const inputStyle = {
  padding: "12px",
  marginBottom: "15px",
  borderRadius: "8px",
  border: "1px solid #1f2937",
  backgroundColor: "#0f172a",
  color: "white",
  width: "100%",
};

const btnStyle = {
  padding: "10px 16px",
  backgroundColor: "#00ccff",
  border: "none",
  borderRadius: "8px",
  color: "black",
  fontWeight: "bold",
  cursor: "pointer",
  fontSize: "14px",
  whiteSpace: "nowrap",
};

const selectStyle = {
  padding: "12px",
  backgroundColor: "#111827",
  color: "#00ccff",
  border: "1px solid #1f2937",
  borderRadius: "8px",
  fontWeight: "bold",
  cursor: "pointer",
  outline: "none",
  minWidth: "200px",
};

const criticalBanner = {
  backgroundColor: "#dc2626",
  padding: "14px",
  textAlign: "center",
  fontWeight: "bold",
  marginBottom: "30px",
  borderRadius: "10px",
};

const statsContainer = {
  display: "flex",
  gap: "20px",
  marginBottom: "40px",
  flexWrap: "wrap",
  justifyContent: "space-between",
};

const middleSection = {
  display: "flex",
  gap: "40px",
  alignItems: "stretch",
  flexWrap: "wrap",
};

const cardStyle = {
  backgroundColor: "#111827",
  padding: "30px",
  borderRadius: "14px",
  border: "1px solid #1f2937",
  boxShadow: "0 0 20px rgba(0,0,0,0.4)",
};

const tableStyle = {
  width: "100%",
  borderCollapse: "collapse",
  textAlign: "left",
};

const rowStyle = {
  borderBottom: "1px solid #1f2937",
  cursor: "pointer",
  transition: "background 0.2s ease",
};

const modalOverlay = {
  position: "fixed",
  top: 0,
  left: 0,
  width: "100%",
  height: "100%",
  backgroundColor: "rgba(0,0,0,0.85)",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  zIndex: 1000,
};

const modalContent = {
  backgroundColor: "#111827",
  padding: "35px",
  borderRadius: "14px",
  border: "1px solid #00ccff",
  boxShadow: "0 0 40px rgba(0,204,255,0.2)",
};

const textAreaStyle = {
  width: "100%",
  height: "200px",
  backgroundColor: "#0f172a",
  color: "#22ff88",
  padding: "15px",
  borderRadius: "10px",
  fontFamily: "monospace",
  border: "1px solid #1f2937",
};

const deleteBtnStyle = {
  background: "none",
  border: "none",
  cursor: "pointer",
  fontSize: "18px",
  padding: "5px",
  borderRadius: "4px",
};
function StatCard({ title, value, color = "white" }) {
  return (
    <div style={{
      backgroundColor: "#1e293b",
      padding: "20px",
      borderRadius: "10px",
      flex: 1,
      minWidth: "160px",
      border: "1px solid #334155"
    }}>
      <h4 style={{
        opacity: 0.7,
        fontSize: "12px",
        marginBottom: "8px"
      }}>
        {title}
      </h4>

      <h2 style={{
        color,
        fontSize: "32px",
        margin: 0
      }}>
        {value}
      </h2>
    </div>
  );
}
function InfoCard({ label, value, highlight }) {
  return (
    <div
      style={{
        backgroundColor: "#0f172a",
        padding: "18px",
        borderRadius: "12px",
        border: "1px solid #1f2937",
        boxShadow: "0 0 10px rgba(0,0,0,0.4)"
      }}
    >
      <div
        style={{
          fontSize: "12px",
          opacity: 0.7,
          marginBottom: "6px",
          letterSpacing: "0.5px"
        }}
      >
        {label}
      </div>

      <div
        style={{
          fontSize: "18px",
          fontWeight: "bold",
          color: highlight || "white"
        }}
      >
        {value}
      </div>
    </div>
  );
}
export default App;