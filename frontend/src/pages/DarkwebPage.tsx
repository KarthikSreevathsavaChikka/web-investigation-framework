import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api";
import { EmptyState, PageHeader, StatCard, StatusBadge, formatDate } from "../components";

type Source = { source_url: string; final_url?: string; status: string; title?: string; error?: string; retrieved_at: string; content_sha256?: string; matches: { field: string; excerpt: string }[] };
type Result = { coverage: string; matched_sources: number; retrieved_sources: number; supplied_sources: number; scope: string; evidence_scope: string; sources: Source[] };
const terminal = ["COMPLETED", "FAILED", "CANCELLED"];

export function DarkwebPage() {
  const [target, setTarget] = useState("");
  const [urls, setUrls] = useState("");
  const [jobId, setJobId] = useState("");
  const entries = [...new Set(urls.split("\n").map((url) => url.trim()).filter(Boolean))];
  const history = useQuery({ queryKey: ["darkweb-jobs"], queryFn: api.jobs, refetchInterval: 5000 });
  const start = useMutation({ mutationFn: api.startDarkweb, onSuccess: (job) => { setJobId(job.id); void history.refetch(); } });
  const live = useQuery({ queryKey: ["darkweb-job", jobId], queryFn: () => api.job(jobId), enabled: Boolean(jobId), refetchInterval: (q) => terminal.includes(q.state.data?.status ?? "") ? false : 2000 });
  const cancel = useMutation({ mutationFn: api.cancelJob, onSuccess: () => { void live.refetch(); } });
  const job = live.data;
  const result = job?.result?.component === "darkweb" ? job.result as unknown as Result : undefined;
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify(job, null, 2)], { type: "application/json" }));
    const a = document.createElement("a"); a.href = url; a.download = `${jobId}.json`; a.click(); URL.revokeObjectURL(url);
  }
  return <>
    <PageHeader eyebrow="Free resources · Tor" title="Dark-web references" description="Check supplied onion pages for exact mentions of a gaming website."/>
    <form className="panel investigation-form" onSubmit={(event) => { event.preventDefault(); start.mutate({ target: target.trim(), onion_urls: entries }); }}>
      <label><span>Gaming URL or domain</span><input required maxLength={500} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="partimatch123.com"/></label>
      <p className="form-help">Find candidate pages using <a href="https://ahmia.fi/" target="_blank" rel="noreferrer">Ahmia (manual search)</a> or your existing investigation sources. Search for the exact domain, then paste the original onion URLs below.</p>
      <div className="bulk-entry"><label><span>Onion source URLs · one per line</span><textarea required rows={5} value={urls} onChange={(e) => setUrls(e.target.value)} placeholder="Paste complete http://…onion/ or https://…onion/ URLs"/></label></div>
      <p className="form-help">{entries.length}/10 sources. Text collection only, with a five-minute run budget. Tor must be configured in the worker. Automatic discovery is not enabled.</p>
      <button className="button primary" disabled={start.isPending || !target.trim() || !entries.length || entries.length > 10}>{start.isPending ? "Queuing…" : "Collect related references"}</button>
      {start.error && <p className="inline-error" role="alert">{start.error.message}</p>}
    </form>
    <section className="panel"><h2>Collection runs</h2>
      {history.error && <p className="inline-error">{history.error.message}</p>}
      <label><span>Open a saved run</span><select value={jobId} onChange={(e) => setJobId(e.target.value)}><option value="">Select a run</option>{(history.data?.items ?? []).filter((j) => j.component === "darkweb").map((j) => <option key={j.id} value={j.id}>{j.target} · {formatDate(j.created_at)} · {j.status}</option>)}</select></label>
      {live.error && <p className="inline-error">{live.error.message}</p>}
      {job && <div aria-live="polite"><p><strong>{job.target}</strong> <StatusBadge status={job.status}/></p>
        {!terminal.includes(job.status) && <><p>Collecting through Tor. Results appear when processing finishes.</p><button className="button" disabled={cancel.isPending || job.status === "CANCELLING"} onClick={() => cancel.mutate(job.id)}>Cancel collection</button></>}
        {job.error && <p className="inline-error">{job.error}</p>}
        {cancel.error && <p className="inline-error">{cancel.error.message}</p>}
      </div>}
    </section>
    {result ? <>
      <section className="stats-grid compact"><StatCard label="Supplied sources" value={result.supplied_sources} hint="Collection scope"/><StatCard label="Assessed pages" value={result.retrieved_sources} hint="Retrieved and checked"/><StatCard label="Matching sources" value={result.matched_sources} hint="Exact domain references"/><StatCard label="Coverage" value={result.coverage} hint="Source availability"/></section>
      <section className="panel"><h2>Evidence</h2><p>{result.scope}</p><p>{result.evidence_scope}</p><button className="button" onClick={download}>Download evidence JSON</button>
        {!result.matched_sources && <p>No exact-domain matches were verified in the supplied sources. Check source statuses for collection gaps.</p>}
        {result.sources.map((source) => <details key={source.source_url}><summary>{source.title || source.source_url} — {source.status.replaceAll("_", " ")}</summary><p>Source: <code>{source.source_url}</code></p><p>Retrieved: {formatDate(source.retrieved_at)}</p>{source.error && <p>{source.error}</p>}{source.content_sha256 && <p>Content SHA-256: <code>{source.content_sha256}</code></p>}{source.matches.map((match, i) => <blockquote key={i}><small>Matched in {match.field}</small><p>{match.excerpt}</p></blockquote>)}</details>)}
      </section>
    </> : <EmptyState title="Evidence will appear here" body="Submit a collection or open a saved run. Only supplied sources are checked."/>}
  </>;
}
