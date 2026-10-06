export type Severity = "Critical" | "High" | "Medium" | "Low" | "Safe";

export type ThreatEvent = {
  id: string;
  timestamp: string;
  source: string;
  subject: string;
  category: string;
  severity: Severity;
  score: number;
  status: "Investigating" | "Contained" | "Resolved" | "New";
  summary: string;
  indicators: string[];
  recommendations: string[];
};

export type AnalysisInput = {
  source: string;
  content: string;
  sender?: string;
  url?: string;
  failed_attempts?: number;
  new_device?: boolean;
  unusual_location?: boolean;
  requests_per_minute?: number;
  baseline_requests_per_minute?: number;
  bytes_out_mb?: number;
  baseline_bytes_out_mb?: number;
  error_rate_percent?: number;
};

export type DashboardSummary = {
  total_events: number;
  events_last_24h: number;
  high_risk_last_24h: number;
  open_events: number;
  severity_counts: Partial<Record<Severity, number>>;
  severity_counts_last_24h: Partial<Record<Severity, number>>;
  category_counts: { category: string; count: number }[];
  hourly_counts: { hour: string; count: number }[];
};
