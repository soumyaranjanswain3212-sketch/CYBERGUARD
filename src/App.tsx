import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertOctagon, ArrowDownRight, ArrowUpRight, Bell, ChevronDown,
  CircleHelp, Clock3, Command, FileSearch, Fingerprint, Globe2, LayoutDashboard,
  LockKeyhole, Menu, MessageSquareWarning, MoreHorizontal, Network, Plus,
  Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles,
  UserRound, X,
} from "lucide-react";
import { activity as demoActivity, initialEvents } from "./data";
import { analyzeEvent, checkHealth, getEvents } from "./api";
import type { AnalysisInput, Severity, ThreatEvent } from "./types";

const navItems = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Threat inbox", icon: ShieldAlert, count: "12" },
  { label: "Identity & access", icon: Fingerprint },
  { label: "URL analysis", icon: Globe2 },
  { label: "Investigations", icon: FileSearch },
];

const severityRank: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Safe: 4 };

function timeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", hour12: false }).format(date);
}

function App() {
  const [events, setEvents] = useState(initialEvents);
  const [apiOnline, setApiOnline] = useState(false);
  const [filter, setFilter] = useState("All events");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ThreatEvent | null>(initialEvents[0]);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [input, setInput] = useState<AnalysisInput>({
    source: "email",
    content: "",
    sender: "",
    url: "",
  });

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const healthy = await checkHealth();
      if (active) setApiOnline(healthy);
      if (!healthy) return;
      try {
        const remoteEvents = await getEvents();
        if (active && remoteEvents.length) {
          setEvents((current) => {
            const added = remoteEvents.filter((item) => !current.some((event) => event.id === item.id));
            return [...added, ...current];
          });
        }
      } catch {
        if (active) setApiOnline(false);
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();
    return events.filter((event) => {
      const matchesFilter = filter === "All events" || event.severity === filter;
      const matchesSearch = !query || `${event.id} ${event.subject} ${event.category} ${event.source}`.toLowerCase().includes(query);
      return matchesFilter && matchesSearch;
    }).sort((a, b) => severityRank[a.severity] - severityRank[b.severity] || b.timestamp.localeCompare(a.timestamp));
  }, [events, filter, search]);

  const threats = events.filter((event) => event.severity === "Critical" || event.severity === "High").length;

  async function submitAnalysis(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setAnalyzing(true);
    try {
      if (!input.content.trim() && !input.url?.trim()) throw new Error("Add message content or a URL to analyze.");
      const result = await analyzeEvent(input);
      setEvents((current) => [result, ...current]);
      setSelected(result);
      setShowAnalyzer(false);
      setInput({ source: "email", content: "", sender: "", url: "" });
      setApiOnline(true);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Analysis could not be completed.");
    } finally {
      setAnalyzing(false);
    }
  }

  function updateStatus(id: string, status: ThreatEvent["status"]) {
    setEvents((current) => current.map((event) => event.id === id ? { ...event, status } : event));
    setSelected((current) => current?.id === id ? { ...current, status } : current);
  }

  return (
    <div className="app-shell">
      {mobileNav && <button className="mobile-scrim" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={20} strokeWidth={2.4} /></div>
          <span>cyber<span className="brand-light">guard</span></span>
          <button className="icon-button sidebar-close" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={17} /></button>
        </div>
        <div className="workspace-switch">
          <div className="workspace-avatar">N</div>
          <div className="workspace-copy"><b>Northstar Labs</b><span>Security workspace</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon, count }) => (
            <button key={label} className={`nav-item ${label === "Overview" ? "active" : ""}`} onClick={() => setMobileNav(false)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{count && <small>{count}</small>}
            </button>
          ))}
        </nav>
        <div className="nav-label tools-label">OPERATIONS</div>
        <button className="nav-item"><Network size={17} strokeWidth={1.8} /><span>Threat intelligence</span></button>
        <button className="nav-item"><Activity size={17} strokeWidth={1.8} /><span>Response playbooks</span></button>
        <div className="sidebar-spacer" />
        <div className="plan-card">
          <div className="plan-icon"><Sparkles size={16} /></div>
          <b>Analyst preview</b>
          <p>Signals are scored with explainable prototype rules.</p>
          <div className="plan-progress"><span /></div>
          <div className="plan-caption"><span>DEMO MODE</span><span>01 / 03</span></div>
        </div>
        <button className="nav-item bottom-nav"><CircleHelp size={17} strokeWidth={1.8} /><span>Help & documentation</span></button>
        <div className="profile">
          <div className="profile-avatar">AS</div>
          <div className="profile-copy"><b>Alex Morgan</b><span>Security analyst</span></div>
          <MoreHorizontal size={18} className="muted-icon" />
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><b>Overview</b></div>
          <div className="topbar-right">
            <div className="status-pill"><span className={`status-dot ${apiOnline ? "online" : ""}`} />{apiOnline ? "Engine connected" : "Demo data"}<span className="status-separator" />Live</div>
            <button className="icon-button top-search" aria-label="Search"><Search size={17} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button>
            <div className="top-avatar">AM</div>
          </div>
        </header>

        <div className="content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" />TUESDAY, OCTOBER 6, 2026</div>
              <h1>Security overview</h1>
              <p className="heading-subtitle">Here's what's happening across your environment today.</p>
            </div>
            <button className="primary-button" onClick={() => { setError(""); setShowAnalyzer(true); }}>
              <Plus size={17} /> Analyze an event <span className="shortcut">⌘ K</span>
            </button>
          </section>

          <section className="metrics-grid" aria-label="Security metrics">
            <Metric icon={<Activity size={17} />} label="Events analyzed" value="2,847" delta="+12.8%" positive detail="vs. previous 24h" />
            <Metric icon={<ShieldAlert size={17} />} label="Threats detected" value={String(threats + 34)} delta="+4.2%" detail="vs. previous 24h" />
            <Metric icon={<LockKeyhole size={17} />} label="High risk blocked" value="28" delta="3 pending" detail="needs analyst review" warning />
            <Metric icon={<UserRound size={17} />} label="Users protected" value="1,204" delta="98.6%" positive detail="of active users" />
          </section>

          <section className="middle-grid">
            <div className="panel trend-panel">
              <div className="panel-heading">
                <div><h2>Threat activity</h2><p>Detection volume across the last 24 hours</p></div>
                <button className="select-button">Last 24 hours <ChevronDown size={14} /></button>
              </div>
              <div className="chart-legend">
                <span><i className="legend-dot phishing" />Phishing</span>
                <span><i className="legend-dot identity" />Identity</span>
                <span><i className="legend-dot endpoint" />Endpoint</span>
                <b><span className="live-pulse" /> LIVE</b>
              </div>
              <div className="chart-area">
                <div className="chart-y-labels"><span>40</span><span>30</span><span>20</span><span>10</span><span>0</span></div>
                <div className="chart-plot">
                  <div className="grid-lines"><i /><i /><i /><i /><i /></div>
                  <svg className="trend-chart" viewBox="0 0 720 182" preserveAspectRatio="none" role="img" aria-label="Threat activity trend chart">
                    <defs>
                      <linearGradient id="fill-a" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#e56c66" stopOpacity=".2" /><stop offset="100%" stopColor="#e56c66" stopOpacity="0" /></linearGradient>
                      <linearGradient id="fill-b" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#d5a44b" stopOpacity=".14" /><stop offset="100%" stopColor="#d5a44b" stopOpacity="0" /></linearGradient>
                    </defs>
                    <path d="M0 143 C35 138 45 148 72 139 S108 126 144 135 S178 119 216 124 S250 132 288 117 S324 100 360 111 S396 96 432 101 S468 70 504 88 S540 98 576 78 S612 84 648 59 S684 74 720 41 L720 182 L0 182Z" fill="url(#fill-a)" />
                    <path d="M0 157 C38 153 44 157 72 151 S108 144 144 150 S180 145 216 146 S252 136 288 143 S324 128 360 137 S396 131 432 126 S468 122 504 128 S540 112 576 118 S612 101 648 108 S684 94 720 99 L720 182 L0 182Z" fill="url(#fill-b)" />
                    <path d="M0 143 C35 138 45 148 72 139 S108 126 144 135 S178 119 216 124 S250 132 288 117 S324 100 360 111 S396 96 432 101 S468 70 504 88 S540 98 576 78 S612 84 648 59 S684 74 720 41" fill="none" stroke="#e56c66" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />
                    <path d="M0 157 C38 153 44 157 72 151 S108 144 144 150 S180 145 216 146 S252 136 288 143 S324 128 360 137 S396 131 432 126 S468 122 504 128 S540 112 576 118 S612 101 648 108 S684 94 720 99" fill="none" stroke="#d5a44b" strokeWidth="2" vectorEffect="non-scaling-stroke" />
                    <path d="M0 169 C38 166 48 172 72 168 S108 164 144 166 S180 157 216 163 S252 167 288 157 S324 162 360 154 S396 159 432 149 S468 153 504 145 S540 150 576 142 S612 146 648 135 S684 142 720 130" fill="none" stroke="#6a8fbe" strokeWidth="1.8" vectorEffect="non-scaling-stroke" />
                    <circle cx="648" cy="59" r="4" fill="#0f151e" stroke="#e56c66" strokeWidth="2" vectorEffect="non-scaling-stroke" />
                  </svg>
                  <div className="chart-x-labels"><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span><span>Now</span></div>
                </div>
              </div>
            </div>
            <div className="panel breakdown-panel">
              <div className="panel-heading">
                <div><h2>Threat breakdown</h2><p>By detection category</p></div>
                <button className="icon-button small-icon" aria-label="More options"><MoreHorizontal size={18} /></button>
              </div>
              <div className="donut-wrap">
                <div className="donut"><div><strong>34</strong><span>threats</span></div></div>
                <div className="donut-center-label"><small>THIS WEEK</small><span>+8.4%</span></div>
              </div>
              <div className="breakdown-legend">
                <Breakdown label="Phishing" percent="41%" value="14" color="phishing" />
                <Breakdown label="Identity fraud" percent="26%" value="9" color="identity" />
                <Breakdown label="Endpoint" percent="21%" value="7" color="endpoint" />
                <Breakdown label="Other" percent="12%" value="4" color="other" />
              </div>
            </div>
          </section>

          <section className="panel events-panel">
            <div className="events-header">
              <div className="panel-heading event-title">
                <div><h2>Recent threat events <span className="event-count">{events.length}</span></h2><p>Review and respond to the latest detections</p></div>
              </div>
              <div className="event-tools">
                <label className="table-search"><Search size={15} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search events..." /></label>
                <label className="filter-select"><SlidersHorizontal size={14} /><select value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter by severity">
                  {["All events", "Critical", "High", "Medium", "Low", "Safe"].map((item) => <option key={item}>{item}</option>)}
                </select><ChevronDown size={13} /></label>
                <button className="icon-button small-icon table-more" aria-label="More event options"><MoreHorizontal size={18} /></button>
              </div>
            </div>
            <div className="table-scroll">
              <table>
                <thead><tr><th>EVENT</th><th>CATEGORY</th><th>SEVERITY</th><th>RISK SCORE</th><th>DETECTED</th><th>STATUS</th><th /></tr></thead>
                <tbody>
                  {filteredEvents.map((event) => (
                    <tr key={event.id} className={selected?.id === event.id ? "selected-row" : ""} onClick={() => setSelected(event)}>
                      <td><div className="event-name"><span className={`event-icon ${event.severity.toLowerCase()}`}><EventIcon category={event.category} /></span><span><b>{event.subject}</b><small>{event.id} <i /> {event.source}</small></span></div></td>
                      <td><span className="category-label">{event.category}</span></td>
                      <td><SeverityBadge severity={event.severity} /></td>
                      <td><div className="score-cell"><div className="score-track"><i className={`score-fill ${event.severity.toLowerCase()}`} style={{ width: `${event.score}%` }} /></div><b>{event.score}</b></div></td>
                      <td className="time-cell">{timeLabel(event.timestamp)}</td>
                      <td><StatusBadge status={event.status} /></td>
                      <td><button className="row-more" aria-label={`Open ${event.id}`} onClick={(e) => { e.stopPropagation(); setSelected(event); }}><MoreHorizontal size={17} /></button></td>
                    </tr>
                  ))}
                  {filteredEvents.length === 0 && <tr><td colSpan={7} className="empty-state">No events match this search.</td></tr>}
                </tbody>
              </table>
            </div>
            <div className="table-footer"><span>Showing <b>{filteredEvents.length}</b> of <b>{events.length}</b> events</span><button onClick={() => { setFilter("All events"); setSearch(""); }}>View all events <ArrowUpRight size={14} /></button></div>
          </section>

          <section className="bottom-grid">
            <div className="panel activity-panel">
              <div className="panel-heading"><div><h2>Live activity</h2><p>Latest signals from your environment</p></div><span className="stream-tag"><span className="live-pulse" /> STREAMING</span></div>
              <div className="activity-list">
                {demoActivity.map((item) => <div className="activity-item" key={item.time}><span className={`activity-marker ${item.kind}`} /><span className="activity-time">{item.time}</span><span className="activity-label">{item.label}</span><ArrowUpRight size={13} className="activity-arrow" /></div>)}
              </div>
            </div>
            <div className="panel response-panel">
              <div className="response-icon"><ShieldCheck size={19} /></div>
              <div><span className="response-kicker">RESPONSE POSTURE</span><h3>You're in good hands.</h3><p>28 high-risk events were contained automatically. 3 need your review.</p><button onClick={() => setFilter("High")}>Review priority queue <ArrowUpRight size={14} /></button></div>
              <div className="response-watermark"><Shield size={95} /></div>
            </div>
          </section>

          <footer className="app-footer"><span><Command size={12} /> CyberGuard <i /> Analyst preview <i /> 1.0.0</span><span>DETECTION ENGINE <b className={apiOnline ? "footer-online" : ""}>{apiOnline ? "CONNECTED" : "DEMO MODE"}</b><span className={`footer-dot ${apiOnline ? "online" : ""}`} /></span></footer>
        </div>
      </main>

      {selected && <aside className="detail-drawer">
        <div className="drawer-top"><div><span className="drawer-kicker">THREAT ASSESSMENT</span><span className="drawer-id">{selected.id}</span></div><button className="icon-button" onClick={() => setSelected(null)} aria-label="Close assessment"><X size={17} /></button></div>
        <div className="drawer-content">
          <SeverityBadge severity={selected.severity} />
          <h2>{selected.subject}</h2>
          <p className="drawer-summary">{selected.summary}</p>
          <div className="risk-card"><div className="risk-number"><strong>{selected.score}</strong><span>/ 100</span></div><div className="risk-copy"><b>Risk score</b><span>Explainable signal-based assessment</span></div><div className="risk-meter"><i style={{ width: `${selected.score}%` }} /></div></div>
          <div className="drawer-section"><div className="section-title"><span>Why this was flagged</span><span className="evidence-count">{selected.indicators.length} SIGNALS</span></div><ul className="evidence-list">{selected.indicators.map((indicator) => <li key={indicator}><span className="evidence-check"><ShieldAlert size={13} /></span>{indicator}</li>)}</ul></div>
          <div className="drawer-section"><div className="section-title"><span>Recommended response</span><span className="ai-tag"><Sparkles size={11} /> GUIDANCE</span></div><ul className="recommendation-list">{selected.recommendations.map((recommendation, index) => <li key={recommendation}><span>{String(index + 1).padStart(2, "0")}</span>{recommendation}</li>)}</ul></div>
          <div className="event-meta"><span><Clock3 size={13} /> Detected {timeLabel(selected.timestamp)}</span><span><Globe2 size={13} /> {selected.source}</span></div>
        </div>
        <div className="drawer-actions">
          {selected.status !== "Resolved" ? <button className="primary-button drawer-primary" onClick={() => updateStatus(selected.id, "Resolved")}><ShieldCheck size={16} /> Mark as resolved</button> : <button className="resolved-button" disabled><ShieldCheck size={16} /> Incident resolved</button>}
          <button className="secondary-button" onClick={() => updateStatus(selected.id, selected.status === "Investigating" ? "New" : "Investigating")}>{selected.status === "Investigating" ? "Move to new" : "Start investigation"}</button>
        </div>
      </aside>}

      {showAnalyzer && <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setShowAnalyzer(false); }}>
        <form className="analyzer-modal" onSubmit={submitAnalysis}>
          <div className="modal-header"><div className="modal-icon"><Sparkles size={19} /></div><div><h2>Analyze an event</h2><p>Inspect a message, URL, identity report, or login signal.</p></div><button type="button" className="icon-button" onClick={() => setShowAnalyzer(false)} aria-label="Close"><X size={18} /></button></div>
          <label className="form-label">Signal type<select value={input.source} onChange={(e) => setInput({ ...input, source: e.target.value })}><option value="email">Email or message</option><option value="url">Website or URL</option><option value="identity">Impersonation / media report</option><option value="auth">Authentication activity</option><option value="network">Network or API activity</option></select></label>
          {input.source === "auth" && <div className="auth-fields"><label className="form-label">Failed attempts<input type="number" min="0" value={input.failed_attempts ?? 0} onChange={(e) => setInput({ ...input, failed_attempts: Number(e.target.value) })} /></label><label className="check-field"><input type="checkbox" checked={input.new_device ?? false} onChange={(e) => setInput({ ...input, new_device: e.target.checked })} /> New device</label><label className="check-field"><input type="checkbox" checked={input.unusual_location ?? false} onChange={(e) => setInput({ ...input, unusual_location: e.target.checked })} /> Unusual location</label></div>}
          <label className="form-label">Content to analyze<textarea rows={5} value={input.content} onChange={(e) => setInput({ ...input, content: e.target.value })} placeholder={input.source === "auth" ? "Optional context about the sign-in event..." : "Paste the message, reported behavior, or other text here..."} /></label>
          {input.source !== "auth" && <label className="form-label">Related URL <span className="optional">(optional)</span><input value={input.url} onChange={(e) => setInput({ ...input, url: e.target.value })} placeholder="https://example.com/sign-in" /></label>}
          {(input.source === "email" || input.source === "identity") && <label className="form-label">Claimed sender <span className="optional">(optional)</span><input value={input.sender ?? ""} onChange={(e) => setInput({ ...input, sender: e.target.value })} placeholder="payroll@example.org" /></label>}
          {error && <div className="form-error"><AlertOctagon size={15} />{error}</div>}
          <div className="modal-note"><Shield size={14} /> Analysis runs locally against transparent prototype heuristics. No content is sent to an external AI service.</div>
          <div className="modal-actions"><button type="button" className="secondary-button" onClick={() => setShowAnalyzer(false)}>Cancel</button><button className="primary-button" disabled={analyzing}>{analyzing ? <><span className="button-spinner" /> Analyzing…</> : <><FileSearch size={16} /> Analyze signal</>}</button></div>
        </form>
      </div>}
    </div>
  );
}

function Metric({ icon, label, value, delta, detail, positive, warning }: { icon: React.ReactNode; label: string; value: string; delta: string; detail: string; positive?: boolean; warning?: boolean }) {
  return <div className="metric-card"><div className="metric-top"><span className="metric-icon">{icon}</span><span className="metric-label">{label}</span><button className="metric-more" aria-label={`${label} details`}><MoreHorizontal size={16} /></button></div><div className="metric-value">{value}</div><div className="metric-bottom"><span className={`metric-delta ${positive ? "positive" : warning ? "caution" : ""}`}>{positive ? <ArrowUpRight size={13} /> : warning ? <Clock3 size={12} /> : <ArrowDownRight size={13} />}{delta}</span><span>{detail}</span></div></div>;
}
function Breakdown({ label, percent, value, color }: { label: string; percent: string; value: string; color: string }) {
  return <div className="breakdown-row"><span className={`legend-dot ${color}`} /><span className="breakdown-name">{label}</span><span className="breakdown-percent">{percent}</span><b>{value}</b></div>;
}
function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity-badge ${severity.toLowerCase()}`}><i />{severity}</span>;
}
function StatusBadge({ status }: { status: ThreatEvent["status"] }) {
  return <span className={`status-badge ${status.toLowerCase()}`}><i />{status}</span>;
}
function EventIcon({ category }: { category: string }) {
  if (category.toLowerCase().includes("account")) return <LockKeyhole size={15} />;
  if (category.toLowerCase().includes("impersonation")) return <MessageSquareWarning size={15} />;
  if (category.toLowerCase().includes("url")) return <Globe2 size={15} />;
  if (category.toLowerCase().includes("api")) return <Network size={15} />;
  if (category.toLowerCase().includes("execution")) return <Activity size={15} />;
  return <MessageSquareWarning size={15} />;
}

export default App;
