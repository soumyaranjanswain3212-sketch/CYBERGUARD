import type { AnalysisInput, DashboardSummary, ThreatEvent } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
let csrfToken = "";
let onSessionExpired: (() => void) | undefined;

export type AnalystSession = { username: string; csrf_token: string };
export type ApiHealth = {
  status: string;
  url_model: { available: boolean; model?: string; threshold?: number };
};

export function setSessionExpiredHandler(handler: () => void) {
  onSessionExpired = handler;
}

async function protectedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (csrfToken && init.method && init.method !== "GET") {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(url, {
    ...init,
    headers,
    credentials: "include",
  });
  if (response.status === 401) {
    csrfToken = "";
    onSessionExpired?.();
  }
  return response;
}

export async function getAnalystSession(): Promise<AnalystSession> {
  const response = await fetch(`${API_BASE}/api/auth/session`, { credentials: "include" });
  if (!response.ok) throw await readError(response);
  const session = await response.json() as AnalystSession;
  csrfToken = session.csrf_token;
  return session;
}

export async function loginAnalyst(username: string, password: string): Promise<AnalystSession> {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) throw await readError(response);
  const session = await response.json() as AnalystSession;
  csrfToken = session.csrf_token;
  return session;
}

export async function logoutAnalyst(): Promise<void> {
  const response = await protectedFetch(`${API_BASE}/api/auth/logout`, { method: "POST" });
  if (!response.ok) throw await readError(response);
  csrfToken = "";
}

export async function checkHealth(): Promise<ApiHealth> {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ApiHealth>;
}

async function readError(response: Response): Promise<Error> {
  const body = (await response.json().catch(() => null)) as { detail?: string } | null;
  return new Error(body?.detail ?? `Request failed (${response.status})`);
}

export async function getEvents(): Promise<ThreatEvent[]> {
  const response = await protectedFetch(`${API_BASE}/api/events?limit=500`);
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ThreatEvent[]>;
}

export async function getSummary(): Promise<DashboardSummary> {
  const response = await protectedFetch(`${API_BASE}/api/summary`);
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<DashboardSummary>;
}

export async function analyzeEvent(input: AnalysisInput): Promise<ThreatEvent> {
  const response = await protectedFetch(`${API_BASE}/api/analyze`, {
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
  const response = await protectedFetch(`${API_BASE}/api/events/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!response.ok) throw await readError(response);
  return response.json() as Promise<ThreatEvent>;
}
