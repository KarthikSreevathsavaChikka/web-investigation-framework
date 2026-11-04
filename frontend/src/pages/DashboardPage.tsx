import { useQuery } from "@tanstack/react-query";
import { ArrowRight, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ErrorState, Loading, PageHeader, StatCard, StatusBadge, formatDate } from "../components";

export function DashboardPage() {
  const investigations = useQuery({ queryKey: ["investigations"], queryFn: api.investigations, refetchInterval: 10000 });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: api.jobs, refetchInterval: 5000 });
  if (investigations.isLoading || jobs.isLoading) return <Loading/>;
  if (investigations.error) return <ErrorState error={investigations.error}/>;
  if (jobs.error) return <ErrorState error={jobs.error}/>;
  const allJobs = jobs.data?.items ?? [];
  const active = allJobs.filter((job) => ["QUEUED", "RUNNING", "CANCELLING"].includes(job.status)).length;
  const failed = allJobs.filter((job) => job.status === "FAILED").length;
  const latest = investigations.data?.items.slice(0, 6) ?? [];
  return <>
    <PageHeader eyebrow="Operations" title="Web scraping overview" description="Monitor scraping activity and open recent evidence reports." actions={<button className="button secondary" onClick={() => { investigations.refetch(); jobs.refetch(); }}><RefreshCw size={17}/>Refresh</button>}/>
    <section className="stats-grid">
      <StatCard label="Scraping results" value={investigations.data?.total ?? 0} hint="Stored target reports"/>
      <StatCard label="Active jobs" value={active} hint="Queued or currently running"/>
      <StatCard label="Completed jobs" value={allJobs.filter((job) => job.status === "COMPLETED").length} hint="Finished worker jobs"/>
      <StatCard label="Failed jobs" value={failed} hint="Require operator review"/>
    </section>
    <section className="panel"><div className="panel-heading"><div><h2>Recent scraping results</h2><p>Latest targets processed by the scraping workers.</p></div><Link to="/investigations" className="text-link">View all <ArrowRight size={16}/></Link></div>
      <div className="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Started</th><th></th></tr></thead><tbody>{latest.map((item) => <tr key={item.id}><td><strong>{item.target}</strong><small>{item.id}</small></td><td><StatusBadge status={item.status}/></td><td>{formatDate(item.started_at)}</td><td><Link className="row-link" to={`/investigations/${item.id}`}>Open <ArrowRight size={15}/></Link></td></tr>)}</tbody></table></div>
    </section>
  </>;
}
