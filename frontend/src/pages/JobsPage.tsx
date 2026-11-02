import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { EmptyState, ErrorState, Loading, PageHeader, StatCard, StatusBadge, formatDate, shortId } from "../components";

export function JobsPage() {
  const query = useQuery({ queryKey: ["jobs"], queryFn: api.jobs, refetchInterval: 5000 });
  if (query.isLoading) return <Loading/>;
  if (query.error) return <ErrorState error={query.error}/>;
  const jobs = (query.data?.items ?? []).filter((job) => job.component === "external");
  return <><PageHeader eyebrow="Complaint system" title="External jobs" description="Live requests received from the external complaint service."/>
    <section className="stats-grid compact"><StatCard label="Received" value={jobs.length} hint="All external requests"/><StatCard label="Running" value={jobs.filter((j) => j.status === "RUNNING").length} hint="Processing now"/><StatCard label="Completed" value={jobs.filter((j) => j.status === "COMPLETED").length} hint="Reports generated"/><StatCard label="Failed" value={jobs.filter((j) => j.status === "FAILED").length} hint="Need attention"/></section>
    <section className="panel no-padding">{jobs.length ? <div className="table-wrap"><table><thead><tr><th>Target</th><th>Local job</th><th>Complaint</th><th>Requested by</th><th>Status</th><th>Received</th><th>Attempts</th></tr></thead><tbody>{jobs.map((job) => <tr key={job.id}><td><strong>{job.target}</strong><small>{String(job.payload.target_id || "")}</small></td><td title={job.id}>{shortId(job.id)}</td><td>{String(job.payload.complaint_id || "Not supplied")}</td><td>{String(job.payload.requested_by || "Not supplied")}</td><td><StatusBadge status={job.status}/></td><td>{formatDate(job.created_at)}</td><td>{job.attempts}</td></tr>)}</tbody></table></div> : <EmptyState title="No external jobs" body="Requests from the complaint system will appear here automatically."/>}</section>
  </>;
}
