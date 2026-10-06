import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertOctagon, ArrowUpRight, Bell, ChevronDown,
  CircleHelp, Clock3, Command, FileSearch, Fingerprint, Globe2, LayoutDashboard,
  LockKeyhole, Menu, MessageSquareWarning, MoreHorizontal, Network, Plus,
  Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles,
  X,
} from "lucide-react";
import { analyzeEvent, checkHealth, getEvents, getSummary, updateEventStatus } from "./api";
import type { AnalysisInput, DashboardSummary, Severity, ThreatEvent } from "./types";

const navItems = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Threat inbox", icon: ShieldAlert },
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
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [apiOnline, setApiOnline] = useState(false);
  const [filter, setFilter] = useState("All events");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [dashboardError, setDashboardError] = useState("");
  const [savingStatus, setSavingStatus] = useState(false);
  const [input, setInput] = useState<AnalysisInput>({
    source: "email",
    content: "",
    sender: "",
    url: "",
  });

  async function refreshDashboard() {
    try {
      const healthy = await checkHealth();
      if (!healthy) throw new Error("CyberGuard API is unavailable.");
      const [remoteEvents, remoteSummary] = await Promise.all([getEvents(), getSummary()]);
      setEvents(remoteEvents);
      setSummary(remoteSummary);
      setApiOnline(true);
      setDashboardError("");
    } catch (reason) {
      setApiOnline(false);
      setDashboardError(reason instanceof Error ? reason.message : "Unable to refresh dashboard data.");
    }
  }

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      if (!active) return;
      await refreshDashboard();
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

  const highRiskEvents = (summary?.severity_counts_last_24h.Critical ?? 0) + (summary?.severity_counts_last_24h.High ?? 0);
  const recentEvents = events.slice(0, 5);
  const categoryBreakdown = useMemo(() => {
    const categories = summary?.category_counts ?? [];
    const total = categories.reduce((sum, item) => sum + item.count, 0);
    if (!total) return [];
    const leading = categories.slice(0, 3).map((item) => ({ ...item, label: item.category }));
    const remaining = categories.slice(3).reduce((sum, item) => sum + item.count, 0);
    if (remaining) leading.push({ category: "Other", label: "Other", count: remaining });
    return leading.map((item, index) => ({
      ...item,
      color: ["#e27069", "#d9a34b", "#6b94c2", "#7e778f"][index],
      percent: Math.round((item.count / total) * 100),
    }));
  }, [summary]);
  const categoryGradient = useMemo(() => {
    let position = 0;
    const stops = categoryBreakdown.map((item) => {
      const start = position;
      position += item.percent;
      return `${item.color} ${start}% ${position}%`;
    });
    return stops.length ? `conic-gradient(${stops.join(", ")})` : "#26313e";
  }, [categoryBreakdown]);
  const maxHourlyCount = Math.max(1, ...(summary?.hourly_counts.map((item) => item.count) ?? []));
  const hourlyPoints = (summary?.hourly_counts ?? []).map((item, index, all) => {
    const x = all.length <= 1 ? 360 : (index / (all.length - 1)) * 720;
    const y = 166 - (item.count / maxHourlyCount) * 140;
    return `${x},${y}`;
  }).join(" ");
  const hourlyArea = hourlyPoints ? `0,182 ${hourlyPoints} 720,182` : "";

  async function submitAnalysis(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setAnalyzing(true);
    try {
      if (input.source === "network") {
        const hasNetworkMetric = input.requests_per_minute !== undefined
          || input.bytes_out_mb !== undefined
          || input.error_rate_percent !== undefined;
        if (!hasNetworkMetric) throw new Error("Add at least one network or API measurement.");
      } else if (input.source !== "auth" && !input.content.trim() && !input.url?.trim()) {
        throw new Error("Add message content or a URL to analyze.");
      }
      const result = await analyzeEvent(input);
      setEvents((current) => [result, ...current]);
      setSummary((current) => current ? {
        ...current,
        total_events: current.total_events + 1,
        events_last_24h: current.events_last_24h + 1,
        high_risk_last_24h: current.high_risk_last_24h + (result.severity === "Critical" || result.severity === "High" ? 1 : 0),
        open_events: current.open_events + 1,
      } : current);
      setSelected(result);
      setShowAnalyzer(false);
      setInput({ source: "email", content: "", sender: "", url: "" });
      setApiOnline(true);
      void refreshDashboard();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Analysis could not be completed.");
    } finally {
      setAnalyzing(false);
    }
  }

  async function updateStatus(id: string, status: ThreatEvent["status"]) {
    setSavingStatus(true);
    setDashboardError("");
    try {
      const updated = await updateEventStatus(id, status);
      setEvents((current) => current.map((event) => event.id === id ? updated : event));
      setSelected((current) => current?.id === id ? updated : current);
      void refreshDashboard();
    } catch (reason) {
      setDashboardError(reason instanceof Error ? reason.message : "Incident status could not be saved.");
    } finally {
      setSavingStatus(false);
    }
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
          <div className="workspace-copy"><b>Local workspace</b><span>Security workspace</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="primary-nav" aria-label="Main navigation">
          {navItems.map(({ label, icon: Icon }) => (
            <button key={label} className={`nav-item ${label === "Overview" ? "active" : ""}`} onClick={() => setMobileNav(false)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
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
          <div className="plan-caption"><span>RULE-BASED</span><span>v1.0</span></div>
        </div>
        <button className="nav-item bottom-nav"><CircleHelp size={17} strokeWidth={1.8} /><span>Help & documentation</span></button>
        <div className="profile">
          <div className="profile-avatar">AS</div>
          <div className="profile-copy"><b>Analyst</b><span>Local session</span></div>
          <MoreHorizontal size={18} className="muted-icon" />
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="icon-button mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="breadcrumb"><span>Workspace</span><span className="crumb-slash">/</span><b>Overview</b></div>
          <div className="topbar-right">
            <div className="status-pill"><span className={`status-dot ${apiOnline ? "online" : ""}`} />{apiOnline ? "API connected" : "API offline"}<span className="status-separator" />30s refresh</div>
            <button className="icon-button top-search" aria-label="Search"><Search size={17} /></button>
            <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button>
            <div className="top-avatar">A</div>
          </div>
        </header>

        <div className="content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" />{new Intl.DateTimeFormat("en", { weekday: "long", month: "long", day: "numeric", year: "numeric" }).format(new Date()).toUpperCase()}</div>
              <h1>Security overview</h1>
              <p className="heading-subtitle">Persisted analysis events from this CyberGuard instance.</p>
            </div>
            <button className="primary-button" onClick={() => { setError(""); setShowAnalyzer(true); }}>
              <Plus size={17} /> Analyze an event <span className="shortcut">⌘ K</span>
            </button>
          </section>
          {dashboardError && <div className="connection-warning" role="status">{dashboardError} {summary ? "Showing the last data successfully loaded." : "No dashboard data has been loaded."}</div>}

          <section className="metrics-grid" aria-label="Security metrics">
            <Metric icon={<Activity size={17} />} label="Events analyzed" value={String(summary?.events_last_24h ?? 0)} detail="Last 24 hours" />
            <Metric icon={<ShieldAlert size={17} />} label="High-risk events" value={String(highRiskEvents)} detail="Critical and High, last 24h" />
            <Metric icon={<LockKeyhole size={17} />} label="Open incidents" value={String(summary?.open_events ?? 0)} detail="New or investigating" />
            <Metric icon={<Clock3 size={17} />} label="All-time events" value={String(summary?.total_events ?? 0)} detail="Persisted analysis records" />
          </section>

          <section className="middle-grid">
            <div className="panel trend-panel">
              <div className="panel-heading">
                <div><h2>Event activity</h2><p>Persisted analyses by hour, last 24 hours</p></div>
                <button className="select-button">Last 24 hours <ChevronDown size={14} /></button>
              </div>
              <div className="chart-legend">
                <span><i className="legend-dot phishing" />Analyzed events</span>
                <b><span className={`status-dot ${apiOnline ? "online" : ""}`} />{apiOnline ? "API DATA" : "OFFLINE"}</b>
              </div>
              <div className="chart-area">
                <div className="chart-y-labels">{[1, 0.75, 0.5, 0.25, 0].map((fraction) => <span key={fraction}>{Math.ceil(maxHourlyCount * fraction)}</span>)}</div>
                <div className="chart-plot">
                  <div className="grid-lines"><i /><i /><i /><i /><i /></div>
                  <svg className="trend-chart" viewBox="0 0 720 182" preserveAspectRatio="none" role="img" aria-label="Persisted analysis events by hour">
                    {hourlyArea && <polygon points={hourlyArea} fill="#e2706930" />}
                    {hourlyPoints && <polyline points={hourlyPoints} fill="none" stroke="#e27069" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />}
                  </svg>
                  <div className="chart-x-labels">{(summary?.hourly_counts ?? []).filter((_, index) => index % 4 === 0).map((item) => <span key={item.hour}>{timeLabel(item.hour)}</span>)}</div>
                </div>
              </div>
            </div>
            <div className="panel breakdown-panel">
              <div className="panel-heading">
                <div><h2>Event breakdown</h2><p>By category, last 24 hours</p></div>
                <button className="icon-button small-icon" aria-label="More options"><MoreHorizontal size={18} /></button>
              </div>
              <div className="donut-wrap">
                <div className="donut" style={{ background: categoryGradient }}><div><strong>{(summary?.category_counts ?? []).reduce((sum, item) => sum + item.count, 0)}</strong><span>events</span></div></div>
              </div>
              <div className="breakdown-legend">
                {categoryBreakdown.map((item) => <Breakdown key={item.label} label={item.label} percent={`${item.percent}%`} value={String(item.count)} color={item.color} />)}
                {!categoryBreakdown.length && <p className="no-category-data">No category data yet.</p>}
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
              <div className="panel-heading"><div><h2>Recent analyses</h2><p>Latest events stored by this instance</p></div><span className="stream-tag"><span className={`status-dot ${apiOnline ? "online" : ""}`} /> POLL 30S</span></div>
              <div className="activity-list">
                {recentEvents.map((item) => <div className="activity-item" key={item.id}><span className={`activity-marker ${item.severity === "Critical" || item.severity === "High" ? "danger" : item.severity === "Medium" ? "warning" : "info"}`} /><span className="activity-time">{timeLabel(item.timestamp)}</span><span className="activity-label">{item.subject}</span><ArrowUpRight size={13} className="activity-arrow" /></div>)}
                {!recentEvents.length && <div className="empty-activity">No analyzed events have been recorded.</div>}
              </div>
            </div>
            <div className="panel response-panel">
              <div className="response-icon"><ShieldCheck size={19} /></div>
              <div><span className="response-kicker">RESPONSE POSTURE</span><h3>Analyst review queue</h3><p>{summary?.open_events ?? 0} open incidents. CyberGuard records recommendations; it does not take response actions automatically.</p><button onClick={() => setFilter("High")}>Review high-risk events <ArrowUpRight size={14} /></button></div>
              <div className="response-watermark"><Shield size={95} /></div>
            </div>
          </section>

          <footer className="app-footer"><span><Command size={12} /> CyberGuard <i /> Rule-based prototype <i /> 1.0.0</span><span>API <b className={apiOnline ? "footer-online" : ""}>{apiOnline ? "CONNECTED" : "OFFLINE"}</b><span className={`footer-dot ${apiOnline ? "online" : ""}`} /></span></footer>
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
          {selected.status !== "Resolved" ? <button className="primary-button drawer-primary" disabled={savingStatus || !apiOnline} onClick={() => void updateStatus(selected.id, "Resolved")}><ShieldCheck size={16} /> {savingStatus ? "Saving…" : "Mark as resolved"}</button> : <button className="resolved-button" disabled><ShieldCheck size={16} /> Incident resolved</button>}
          <button className="secondary-button" disabled={savingStatus || !apiOnline} onClick={() => void updateStatus(selected.id, selected.status === "Investigating" ? "New" : "Investigating")}>{selected.status === "Investigating" ? "Move to new" : "Start investigation"}</button>
        </div>
      </aside>}

      {showAnalyzer && <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setShowAnalyzer(false); }}>
        <form className="analyzer-modal" onSubmit={submitAnalysis}>
          <div className="modal-header"><div className="modal-icon"><Sparkles size={19} /></div><div><h2>Analyze an event</h2><p>Inspect a message, URL, identity report, or telemetry measurement.</p></div><button type="button" className="icon-button" onClick={() => setShowAnalyzer(false)} aria-label="Close"><X size={18} /></button></div>
          <label className="form-label">Signal type<select value={input.source} onChange={(e) => setInput({ ...input, source: e.target.value })}><option value="email">Email or message</option><option value="url">Website or URL</option><option value="identity">Impersonation / media report</option><option value="auth">Authentication activity</option><option value="network">Network or API activity</option></select></label>
          {input.source === "auth" && <div className="auth-fields"><label className="form-label">Failed attempts<input type="number" min="0" value={input.failed_attempts ?? 0} onChange={(e) => setInput({ ...input, failed_attempts: Number(e.target.value) })} /></label><label className="check-field"><input type="checkbox" checked={input.new_device ?? false} onChange={(e) => setInput({ ...input, new_device: e.target.checked })} /> New device</label><label className="check-field"><input type="checkbox" checked={input.unusual_location ?? false} onChange={(e) => setInput({ ...input, unusual_location: e.target.checked })} /> Unusual location</label></div>}
          {input.source === "network" && <div className="network-fields">
            <p className="field-hint">Enter observed telemetry and its usual baseline where applicable. These values are analyzed by the API and saved with the resulting event.</p>
            <div className="auth-fields">
              <label className="form-label">Requests / minute<input type="number" min="0" max="10000000" value={input.requests_per_minute ?? ""} onChange={(e) => setInput({ ...input, requests_per_minute: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
              <label className="form-label">Baseline requests / min<input type="number" min="1" max="10000000" value={input.baseline_requests_per_minute ?? ""} onChange={(e) => setInput({ ...input, baseline_requests_per_minute: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
              <label className="form-label">Outbound data (MB)<input type="number" min="0" step="any" value={input.bytes_out_mb ?? ""} onChange={(e) => setInput({ ...input, bytes_out_mb: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
              <label className="form-label">Baseline outbound (MB)<input type="number" min="0.001" step="any" value={input.baseline_bytes_out_mb ?? ""} onChange={(e) => setInput({ ...input, baseline_bytes_out_mb: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
              <label className="form-label">API error rate (%)<input type="number" min="0" max="100" step="any" value={input.error_rate_percent ?? ""} onChange={(e) => setInput({ ...input, error_rate_percent: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
            </div>
          </div>}
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

function Metric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) {
  return <div className="metric-card"><div className="metric-top"><span className="metric-icon">{icon}</span><span className="metric-label">{label}</span></div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{detail}</span></div></div>;
}
function Breakdown({ label, percent, value, color }: { label: string; percent: string; value: string; color: string }) {
  return <div className="breakdown-row"><span className="legend-dot" style={{ background: color }} /><span className="breakdown-name">{label}</span><span className="breakdown-percent">{percent}</span><b>{value}</b></div>;
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
