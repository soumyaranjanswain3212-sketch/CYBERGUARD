import type { AnalysisInput, DashboardSummary, ThreatEvent } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

async function readError(response: Response): Promise<Error> {
  const body = (await response.json().catch(() => null)) as { detail?: string } | null;
  return new Error(body?.detail ?? `Request failed (${response.status})`);
}

export async function getEvents(): Promise<ThreatEvent[]> {
  const response = await fetch(`${API_BASE}/api/events?limit=500`);
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ThreatEvent[]>;
}

export async function getSummary(): Promise<DashboardSummary> {
  const response = await fetch(`${API_BASE}/api/summary`);
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<DashboardSummary>;
}

export async function analyzeEvent(input: AnalysisInput): Promise<ThreatEvent> {
  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ThreatEvent>;
}

export async function updateEventStatus(
  id: string,
  status: ThreatEvent["status"],
): Promise<ThreatEvent> {
  const response = await fetch(`${API_BASE}/api/events/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ThreatEvent>;
}
