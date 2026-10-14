import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download, ExternalLink, Eye } from "lucide-react";
import { ReactNode, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { EmptyState, ErrorState, Loading, PageHeader, StatCard, StatusBadge, formatDate } from "../components";
import type { InvestigationResults } from "../types";

const sections = [
  ["overview", "Overview"], ["domains", "Domains"], ["findings", "Findings"],
  ["evidence", "Evidence captures"], ["queries", "Search queries"], ["sources", "Sources"],
  ["documents", "Documents"], ["collectors", "Collector status"], ["risks", "Risk analysis"], ["notes", "Analyst notes"],
] as const;
type Section = typeof sections[number][0];
const text = (value: unknown, fallback = "Not available") => value === null || value === undefined || value === "" ? fallback : String(value);
const url = (value: unknown) => typeof value === "string" && /^https?:\/\//.test(value) ? value : "";

export function InvestigationPage() {
  const { id = "" } = useParams();
  const [section, setSection] = useState<Section>("overview");
  const query = useQuery({ queryKey: ["investigation", id], queryFn: () => api.investigation(id), enabled: Boolean(id), refetchInterval: (q) => q.state.data?.investigation.status === "RUNNING" ? 5000 : false });
  if (query.isLoading) return <Loading/>;
  if (query.error) return <ErrorState error={query.error}/>;
  const data = query.data!;
  const investigation = data.investigation;
  const count = (name: string) => data.summary[name] ?? 0;
  return <>
    <Link to="/investigations" className="back-link"><ArrowLeft size={16}/>Scraping results</Link>
    <PageHeader eyebrow={data.id} title={text(investigation.target_domain, "Web scraping result")} description={`Started ${formatDate(text(investigation.started_at, ""))}`} actions={<div className="report-actions"><StatusBadge status={text(investigation.status, "Unknown")}/><a className="button secondary" href={reportUrl(data.id, "html", false)} target="_blank" rel="noreferrer"><Eye size={16}/>View report</a><div className="download-menu"><button className="button primary"><Download size={16}/>Download report</button><div>{["json", "html", "docx", "csv"].map((format) => <a key={format} href={reportUrl(data.id, format, true)}>{format.toUpperCase()}</a>)}</div></div></div>}/>
    <nav className="section-tabs" aria-label="Scraping result sections">{sections.map(([key, label]) => <button key={key} className={section === key ? "active" : ""} onClick={() => setSection(key)}>{label}<span>{sectionCount(data, key)}</span></button>)}</nav>
    <ResultSection data={data} section={section} count={count}/>
  </>;
}

function sectionCount(data: InvestigationResults, section: Section) {
  const map: Partial<Record<Section, number>> = { domains: data.domains.length, findings: data.findings.length, evidence: data.evidence.length, queries: data.queries.length, sources: data.sources.length, documents: data.documents.length, collectors: data.collector_runs.length, risks: data.risk_indicators.length, notes: data.analyst_notes.length };
  return map[section] ?? "";
}

function ResultSection({ data, section, count }: { data: InvestigationResults; section: Section; count: (name: string) => number }) {
  if (section === "overview") return <>
    <section className="stats-grid"><StatCard label="Search results" value={count("raw_search_results")} hint="Returned before filtering"/><StatCard label="Relevant sources" value={count("accepted_sources")} hint="Passed target validation"/><StatCard label="Pages visited" value={count("pages_visited")} hint="Opened by browser workers"/><StatCard label="Screenshots" value={count("screenshots_captured")} hint="Stored visual evidence"/></section>
    <section className="panel"><div className="panel-heading"><div><h2>Collection coverage</h2><p>{text(data.investigation.coverage?.message, "No coverage message was stored.")}</p></div><StatusBadge status={text(data.investigation.coverage?.status, "Unknown")}/></div></section>
    <section className="panel"><h2>Scraping funnel</h2><div className="funnel"><Metric label="Queries configured" value={count("configured_queries")}/><Metric label="Results reviewed" value={count("raw_search_results")}/><Metric label="Target-related sources" value={count("accepted_sources")}/><Metric label="Evidence confirmed" value={count("confirmed_evidence")}/></div></section>
  </>;
  if (section === "domains") return <DataTable empty="No candidate domains were stored." columns={["Domain", "Confidence", "Status", "HTTP", "Monthly visits", "Reason"]} rows={data.domains.map((d) => [<strong>{text(d.domain)}</strong>, `${Math.round(Number(d.confidence || 0) * 100)}%`, text(d.detailed_status || d.domain_status), text(d.http_status), text(d.monthly_visits), text(d.reason)])}/>;
  if (section === "findings") return data.findings.length ? <div className="result-list">{data.findings.map((f, i) => <article className="result-card evidence-card" key={text(f.id, String(i))}><h3>{text(f.title, text(f.platform))}</h3>{Array.isArray(f.screenshot_urls) && f.screenshot_urls.map((shot, index) => <div key={text(shot)}><img src={text(shot)} alt={`${text(f.platform)} highlighted capture`} loading="lazy"/><div className="screenshot-summary"><strong>Screenshot summary</strong><p>{text(Array.isArray(f.screenshot_summaries) ? f.screenshot_summaries[index] : "", "Summary unavailable for this screenshot.")}</p></div></div>)}{(!Array.isArray(f.screenshot_urls) || !f.screenshot_urls.length) && <p>{text(f.post_text || f.search_snippet)}</p>}<small>{text(f.platform)} · {Math.round(Number(f.confidence || 0) * 100)}% confidence · {text(f.status)}</small>{url(f.post_url) && <a href={url(f.post_url)} target="_blank" rel="noreferrer">Open source <ExternalLink size={14}/></a>}</article>)}</div> : <EmptyState title="Nothing to display" body="No automated social or review findings were stored."/>;
  if (section === "evidence") return data.evidence.length ? <div className="result-list">{data.evidence.map((e, i) => { const hasScreenshot = typeof e.screenshot_url === "string" && Boolean(e.screenshot_url); return <article className="result-card evidence-card" key={text(e.id, String(i))}><h3>{text(e.page_title, text(e.query_name))}</h3>{hasScreenshot && <img src={text(e.screenshot_url)} alt={`Highlighted evidence captured from ${text(e.page_title, "source page")}`} loading="lazy"/>}{hasScreenshot && <div className="screenshot-summary"><strong>Screenshot summary</strong><p>{text(e.screenshot_summary, "Summary unavailable for this screenshot.")}</p></div>}{!hasScreenshot && <p>{text(e.context_text || e.evidence_text)}</p>}<small>{text(e.query_category)} · {Math.round(Number(e.confidence || 0) * 100)}% confidence · {text(e.accessibility_status)}</small>{url(e.final_url || e.source_url) && <a href={url(e.final_url || e.source_url)} target="_blank" rel="noreferrer">Open source <ExternalLink size={14}/></a>}</article>;})}</div> : <EmptyState title="Nothing to display" body="No confirmed evidence captures were stored."/>;
  if (section === "queries") return <DataTable empty="No search queries were stored." columns={["ID", "Query", "Category", "Priority", "Provider"]} rows={data.queries.map((q) => [text(q.query_id), text(q.query), text(q.category), text(q.priority), text(q.provider)])}/>;
  if (section === "sources") return <CardList empty="No target-related sources passed validation." items={data.sources.map((s) => ({ title: text(s.title, text(s.source_type)), body: text(s.snippet), meta: `${text(s.source_type)} · discovered by ${text(s.discovered_by_queries, "0")} queries`, link: url(s.source_url) }))}/>;
  if (section === "documents") return <CardList empty="No public documents were downloaded." items={data.documents.map((d) => ({ title: text(d.file_name, text(d.document_type)), body: text(d.evidence_context), meta: `${text(d.relevance_status)} · ${text(d.size_bytes, "0")} bytes`, link: url(d.final_url || d.source_url) }))}/>;
  if (section === "collectors") return <DataTable empty="No collector executions were recorded." columns={["Collector", "Status", "Duration", "Observations", "Message"]} rows={data.collector_runs.map((c) => [text(c.collector), <StatusBadge status={text(c.status)}/>, `${text(c.duration_seconds, "0")} s`, text(c.observation_count, "0"), text(c.error, "Completed without an error")])}/>;
  if (section === "risks") return <><section className="panel risk-notice"><h2>Evidence-based indicators</h2><p>Scores describe collected indicators. Missing or blocked evidence does not establish that a target is safe.</p></section><DataTable empty="No risk indicators were produced from the collected evidence." columns={["Category", "Indicator", "Value", "Points", "Confidence"]} rows={data.risk_indicators.map((r) => [text(r.category), text(r.indicator), text(r.value), text(r.points, "0"), `${Math.round(Number(r.confidence || 0) * 100)}%`])}/></>;
  return <CardList empty="No analyst notes have been added." items={data.analyst_notes.map((n) => ({ title: formatDate(text(n.created_at, "")), body: text(n.note), meta: "Analyst note" }))}/>;
}

function Metric({ label, value }: { label: string; value: number }) { return <div><strong>{value}</strong><span>{label}</span></div>; }
function DataTable({ columns, rows, empty }: { columns: string[]; rows: ReactNode[][]; empty: string }) { return rows.length ? <section className="panel no-padding"><div className="table-wrap"><table><thead><tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>)}</tbody></table></div></section> : <EmptyState title="Nothing to display" body={empty}/>; }
function CardList({ items, empty }: { items: { title: string; body: string; meta: string; link?: string }[]; empty: string }) { return items.length ? <div className="result-list">{items.map((item, i) => <article className="result-card" key={`${item.title}-${i}`}><h3>{item.title}</h3><p>{item.body}</p><small>{item.meta}</small>{item.link && <a href={item.link} target="_blank" rel="noreferrer">Open source <ExternalLink size={14}/></a>}</article>)}</div> : <EmptyState title="Nothing to display" body={empty}/>; }
function reportUrl(id: string, format: string, download: boolean) { return `/api/v1/investigations/osint/${encodeURIComponent(id)}/reports/${format}?download=${download}`; }
