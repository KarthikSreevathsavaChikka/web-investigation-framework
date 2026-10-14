export type Status = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLING" | "CANCELLED" | "PARTIAL";

export interface InvestigationSummary {
  id: string;
  component: "osint";
  target: string;
  status: Status | string;
  started_at: string | null;
  completed_at: string | null;
}

export interface InvestigationDetail {
  id: string;
  component: "osint";
  investigation: Record<string, unknown> & { target_domain?: string; status?: string; coverage?: { status?: string; message?: string } };
  summary: Record<string, number>;
}

export interface InvestigationResults extends InvestigationDetail {
  domains: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
  page_captures: Record<string, unknown>[];
  screenshot_summaries: Record<string, unknown>[];
  queries: Record<string, unknown>[];
  query_metrics: Record<string, unknown>[];
  sources: Record<string, unknown>[];
  documents: Record<string, unknown>[];
  collector_runs: Record<string, unknown>[];
  risk_indicators: Record<string, unknown>[];
  analyst_notes: Record<string, unknown>[];
}

export interface Job {
  id: string;
  component: "osint" | "virustotal" | "external" | "darkweb";
  target: string;
  status: Status;
  attempts: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  payload: Record<string, unknown>;
  result: Record<string, unknown>;
  error: string | null;
}

export interface ListResponse<T> { items: T[]; total: number }
