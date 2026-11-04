import type { InvestigationResults, InvestigationSummary, Job, ListResponse } from "./types";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...options, headers: { Accept: "application/json", "Content-Type": "application/json", ...options?.headers } });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string | { msg: string }[] } | null;
    const detail = Array.isArray(body?.detail) ? body.detail.map((item) => item.msg).join("; ") : body?.detail;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  startDarkweb: (input: { target: string; onion_urls: string[] }) => request<Job>("/api/v1/jobs/darkweb", { method: "POST", body: JSON.stringify({ ...input, authorized: true }) }),
  investigations: () => request<ListResponse<InvestigationSummary>>("/api/v1/investigations?component=osint&limit=200"),
  investigation: (id: string) => request<InvestigationResults>(`/api/v1/investigations/osint/${encodeURIComponent(id)}/results`),
  startInvestigation: (input: { target: string; brand: string; query_budget: number; collectors: string[] }) => request<Job>("/api/v1/jobs/osint", { method: "POST", body: JSON.stringify({ ...input, authorized: true }) }),
  jobs: () => request<ListResponse<Job>>("/api/v1/jobs?limit=200"),
  job: (id: string) => request<Job>(`/api/v1/jobs/${encodeURIComponent(id)}`),
  cancelJob: (id: string) => request<Job>(`/api/v1/jobs/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  health: () => request<{ status: string; service: string }>("/health/ready"),
};
