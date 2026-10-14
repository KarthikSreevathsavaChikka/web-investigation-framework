import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, Eye, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { EmptyState, ErrorState, Loading, PageHeader, StatusBadge, formatDate } from "../components";
import type { InvestigationSummary, Job, Status } from "../types";

interface ScrapeRow {
  key: string;
  target: string;
  status: Status | string;
  submittedAt: string | null;
  startedAt: string | null;
  completedAt: string | null;
  jobId?: string;
  reportId?: string;
  queuePosition?: number;
  error?: string | null;
}

function reportId(job: Job): string | undefined {
  const value = job.result?.investigation_id;
  return typeof value === "string" && value ? value : undefined;
}

function reportUrl(id: string, format: "html" | "docx", download: boolean) {
  return `/api/v1/investigations/osint/${encodeURIComponent(id)}/reports/${format}?download=${download}`;
}

export function InvestigationsPage() {
  const [filter, setFilter] = useState("");
  const queryClient = useQueryClient();
  const reportsQuery = useQuery({ queryKey: ["investigations"], queryFn: api.investigations, refetchInterval: 5000 });
  const jobsQuery = useQuery({ queryKey: ["jobs"], queryFn: api.jobs, refetchInterval: 5000 });
  const cancelMutation = useMutation({
    mutationFn: api.cancelJob,
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["jobs"] }),
        queryClient.invalidateQueries({ queryKey: ["investigations"] }),
      ]);
    },
  });
  const rows = useMemo(() => {
    const jobs = (jobsQuery.data?.items ?? []).filter((job) => job.component === "osint");
    const queued = jobs.filter((job) => job.status === "QUEUED").sort((a, b) => a.created_at.localeCompare(b.created_at));
    const positions = new Map(queued.map((job, index) => [job.id, index + 1]));
    const linkedReports = new Set(jobs.map(reportId).filter((id): id is string => Boolean(id)));
    const jobRows: ScrapeRow[] = jobs.map((job) => ({
      key: job.id,
      target: job.target,
      status: job.status,
      submittedAt: job.created_at,
      startedAt: job.started_at,
      completedAt: job.completed_at,
      jobId: job.id,
      reportId: reportId(job),
      queuePosition: positions.get(job.id),
      error: job.error,
    }));
    const historicalRows: ScrapeRow[] = (reportsQuery.data?.items ?? [])
      .filter((report: InvestigationSummary) => !linkedReports.has(report.id))
      .map((report: InvestigationSummary) => ({
        key: report.id,
        target: report.target,
        status: report.status,
        submittedAt: report.started_at,
        startedAt: report.started_at,
        completedAt: report.completed_at,
        reportId: report.id,
      }));
    return [...jobRows, ...historicalRows]
      .sort((a, b) => String(b.submittedAt ?? "").localeCompare(String(a.submittedAt ?? "")))
      .filter((item) => `${item.target} ${item.jobId ?? ""} ${item.reportId ?? ""} ${item.status}`.toLowerCase().includes(filter.toLowerCase()));
  }, [jobsQuery.data, reportsQuery.data, filter]);
  if (reportsQuery.isLoading || jobsQuery.isLoading) return <Loading/>;
  if (reportsQuery.error) return <ErrorState error={reportsQuery.error}/>;
  if (jobsQuery.error) return <ErrorState error={jobsQuery.error}/>;
  return <><PageHeader eyebrow="Evidence" title="Scraping results" description="Track every submitted target from the queue through report completion."/>
    <div className="toolbar"><label className="search-field"><Search size={18}/><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Search by target, status, or ID" aria-label="Search scraping results"/></label><span>{rows.length} results</span></div>
    {cancelMutation.error && <div className="inline-error job-action-error">{cancelMutation.error.message}</div>}
    <section className="panel no-padding">{rows.length ? <div className="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Queue</th><th>Submitted</th><th>Started</th><th>Completed</th><th>Actions</th></tr></thead><tbody>{rows.map((item) => {
      const canCancel = item.jobId && ["QUEUED", "RUNNING", "CANCELLING"].includes(item.status);
      return <tr key={item.key}><td><div className="target-cell"><strong>{/^https?:\/\//i.test(item.target) ? <a href={item.target} target="_blank" rel="noopener noreferrer">{item.target}</a> : item.target}</strong><small title={item.jobId ?? item.reportId}>Job ID: {item.jobId ?? item.reportId}</small>{item.error && <small className="job-error" title={item.error}>{item.error}</small>}</div></td><td><StatusBadge status={item.status}/></td><td>{item.queuePosition ? `#${item.queuePosition}` : "—"}</td><td>{formatDate(item.submittedAt)}</td><td>{formatDate(item.startedAt)}</td><td>{formatDate(item.completedAt)}</td><td><div className="table-actions">{item.reportId && <><Link className="row-link" to={`/investigations/${item.reportId}`}><Eye size={15}/>View report</Link><a className="row-link" href={reportUrl(item.reportId, "docx", true)}><Download size={15}/>Download</a></>}{canCancel && <button className="text-button danger" disabled={item.status === "CANCELLING" || cancelMutation.isPending} onClick={() => cancelMutation.mutate(item.jobId!)}><X size={15}/>{item.status === "CANCELLING" ? "Stopping…" : "Cancel"}</button>}{!item.reportId && !canCancel && <span className="muted">—</span>}</div></td></tr>;
    })}</tbody></table></div> : <EmptyState title="No matching scraping results" body="Try a different target, job ID, or status."/>}</section>
  </>;
}
