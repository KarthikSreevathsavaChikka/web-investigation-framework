import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, LoaderCircle, Play } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { PageHeader, StatusBadge } from "../components";

const collectors = [
  "DNS", "RDAP", "Public website", "Certificate Transparency (crt.sh)",
  "Wayback historical URLs", "Keyless Web Search (no API key)",
  "X/Twitter authenticated search", "Instagram authenticated search",
  "Facebook authenticated search", "Telegram authenticated search",
  "YouTube authenticated search", "Quora authenticated search", "Trustpilot public reviews",
];
const depths = { Fast: 12, Balanced: 25, Deep: 100 } as const;

export function NewInvestigationPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<"single" | "bulk">("single");
  const [bulkUrls, setBulkUrls] = useState("");
  const [bulkResults, setBulkResults] = useState<{ url: string; jobId?: string; error?: string }[]>([]);
  const [bulkPending, setBulkPending] = useState(false);
  const [brand, setBrand] = useState("");
  const [depth, setDepth] = useState<keyof typeof depths>("Balanced");
  const [selected, setSelected] = useState([...collectors]);
  const allSelected = selected.length === collectors.length;
  const mutation = useMutation({ mutationFn: api.startInvestigation });
  const liveJob = useQuery({
    queryKey: ["job", mutation.data?.id],
    queryFn: () => api.job(mutation.data!.id),
    enabled: Boolean(mutation.data?.id),
    refetchInterval: (query) => ["COMPLETED", "FAILED", "CANCELLED"].includes(query.state.data?.status ?? "") ? false : 2000,
  });
  const submittedJob = liveJob.data ?? mutation.data;
  function submit(event: FormEvent) {
    event.preventDefault();
    if (mode === "bulk") { void submitBulk(); return; }
    mutation.mutate({ target: target.trim(), brand: brand.trim(), query_budget: depths[depth], collectors: selected });
  }
  function toggle(value: string) { setSelected((current) => current.includes(value) ? current.filter((item) => item !== value) : [...current, value]); }
  const entries = [...new Set(bulkUrls.split(/[\n,]+/).map((value) => value.trim()).filter(Boolean))];
  const invalidEntries = entries.filter((value) => { try { const url = new URL(value); return !["http:", "https:"].includes(url.protocol) || !url.hostname || value.length > 500; } catch { return true; } });
  async function submitBulk() {
    if (!entries.length || entries.length > 25 || invalidEntries.length || !selected.length) return;
    setBulkPending(true);
    setBulkResults([]);
    const results = await Promise.all(entries.map(async (url) => {
      try {
        const job = await api.startInvestigation({ target: url, brand: brand.trim(), query_budget: depths[depth], collectors: selected });
        return { url, jobId: job.id };
      } catch (error) {
        return { url, error: error instanceof Error ? error.message : "Could not queue URL" };
      }
    }));
    setBulkResults(results);
    setBulkPending(false);
  }
  return <>
    <PageHeader eyebrow="Start" title="New web scrape" description="Enter one target or paste multiple URLs to collect public evidence."/>
    <form className="panel investigation-form" onSubmit={submit}>
      <div className="target-mode" role="group" aria-label="Target entry mode"><button type="button" className={mode === "single" ? "active" : ""} aria-pressed={mode === "single"} onClick={() => setMode("single")}>Single target</button><button type="button" className={mode === "bulk" ? "active" : ""} aria-pressed={mode === "bulk"} onClick={() => setMode("bulk")}>Bulk URLs</button></div>
      {mode === "single" ? <div className="form-grid"><label><span>Target URL, domain, or brand</span><input required value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com or Example Brand"/></label><label><span>Brand name <small>optional</small></span><input value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="Used to improve relevance matching"/></label></div> : <div className="bulk-entry"><label><span>URLs (one per line or comma separated)</span><textarea required value={bulkUrls} onChange={(event) => setBulkUrls(event.target.value)} placeholder={"https://example.com\nhttps://another.example/page"} rows={6}/></label><p className="form-help">Up to 25 unique URLs. Each URL creates a separate investigation.</p><label><span>Brand name <small>optional</small></span><input value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="Used to improve relevance matching"/></label>{invalidEntries.length > 0 && <div className="inline-error">Enter complete http(s) URLs: {invalidEntries.slice(0, 3).join(", ")}</div>}{entries.length > 25 && <div className="inline-error">Enter no more than 25 URLs at a time.</div>}</div>}
      <fieldset><legend>Discovery depth</legend><div className="choice-grid">{Object.entries(depths).map(([name, budget]) => <button type="button" key={name} className={depth === name ? "choice active" : "choice"} onClick={() => setDepth(name as keyof typeof depths)}><strong>{name}</strong><span>{budget === 100 ? "All enabled" : budget} search queries</span></button>)}</div></fieldset>
      <fieldset><div className="fieldset-heading"><legend>Evidence collectors</legend><label className="check-all"><input type="checkbox" checked={allSelected} onChange={() => setSelected(allSelected ? [] : [...collectors])}/><span>{allSelected ? "Unselect all" : "Select all"}</span></label></div><div className="collector-grid">{collectors.map((item) => <label className="check" key={item}><input type="checkbox" checked={selected.includes(item)} onChange={() => toggle(item)}/><span>{item}</span></label>)}</div></fieldset>
      <p className="form-help">Authenticated social collectors require a saved browser session. The scrape still runs when an individual collector is unavailable and reports its status.</p>
      <button className="button primary" disabled={mode === "bulk" ? !entries.length || entries.length > 25 || Boolean(invalidEntries.length) || !selected.length || bulkPending : !target.trim() || !selected.length || mutation.isPending}><Play size={17}/>{mode === "bulk" ? bulkPending ? "Queuing…" : `Queue ${entries.length} URL${entries.length === 1 ? "" : "s"}` : mutation.isPending ? "Starting…" : "Start evidence discovery"}</button>
      {mode === "single" && mutation.error && <div className="inline-error">{mutation.error.message}</div>}
      {mode === "single" && submittedJob && <div className={`job-feedback job-feedback-${submittedJob.status.toLowerCase()}`}>
        {submittedJob.status === "FAILED" || submittedJob.status === "CANCELLED" ? <AlertCircle/> : submittedJob.status === "COMPLETED" ? <CheckCircle2/> : <LoaderCircle className="spin"/>}
        <div><strong>{submittedJob.status === "QUEUED" ? "Web scrape queued" : submittedJob.status === "RUNNING" ? "Web scrape running" : submittedJob.status === "COMPLETED" ? "Web scrape completed" : submittedJob.status === "CANCELLING" ? "Stopping web scrape" : submittedJob.status === "CANCELLED" ? "Web scrape cancelled" : "Web scrape failed"}</strong>
          <p>Job {submittedJob.id} <StatusBadge status={submittedJob.status}/></p>
          {submittedJob.error && <p>{submittedJob.error}</p>}
          {typeof submittedJob.result?.investigation_id === "string" && <Link to={`/investigations/${submittedJob.result.investigation_id}`}>View completed report</Link>}
          {typeof submittedJob.result?.investigation_id !== "string" && <Link to="/investigations">Open scraping results</Link>}
        </div>
      </div>}
      {mode === "bulk" && bulkResults.length > 0 && <div className="bulk-results" aria-live="polite"><strong>Queued {bulkResults.filter((result) => result.jobId).length} of {bulkResults.length} URLs</strong><ul>{bulkResults.map((result) => <li key={result.url}>{result.url}: {result.jobId ? <span>Queued ({result.jobId})</span> : <span className="inline-error">{result.error}</span>}</li>)}</ul><Link to="/investigations">Open scraping results</Link></div>}
    </form>
  </>;
}
