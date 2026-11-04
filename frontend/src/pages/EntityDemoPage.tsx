import { ExtractionDetails } from "./ExtractionDetails";
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { PageHeader, Loading, ErrorState } from '../components';

type Match = {investigation_id: string; target?: string; kind: string; value: string; source: string; matching_source: string};
type Results = {index_status?: {status: string; detail: string}; indexed_investigations?: number; total_investigations?: number; extractions: {id: string; source: string; result: {status: string; text?: string; pages?: {page: number; qr_contents: string}[]}}[]; connections: Match[]};
const labels: Record<string, string> = {email: 'Email address', payment: 'Payment identifier', phone: 'Phone number', social: 'Social URL', domain: 'Source domain'};
function SourceLink({value}: {value: string}) {
 return /^https?:\/\//i.test(value) ? <a href={value} target="_blank" rel="noreferrer">{value} ↗</a> : <span>{value || 'Source unavailable'}</span>;
}
export function EnrichmentResults({id}: {id: string}) {
 const [showDomains, setShowDomains] = useState(false);
 const query = useQuery({queryKey: ['entities', id], refetchInterval: 10000, queryFn: async () => {const r = await fetch('/api/v1/entities/' + encodeURIComponent(id)); if (!r.ok) throw new Error('Entity results unavailable'); return r.json() as Promise<Results>;}});
 if(query.isLoading) return <Loading/>;
 if(query.error) return <ErrorState error={query.error}/>;
 const data = query.data!;
 const domainCount = data.connections.filter(c => c.kind === 'domain').length;
 const groups = new Map<string, {target: string; matches: Map<string, Match[]>}>();
 for(const c of data.connections) {
   if(c.kind === 'domain' && !showDomains) continue;
   if(!groups.has(c.investigation_id)) groups.set(c.investigation_id, {target: c.target || c.investigation_id, matches: new Map()});
   const matches = groups.get(c.investigation_id)!.matches;
   const key = JSON.stringify([c.kind, c.value]);
   if(!matches.has(key)) matches.set(key, []);
   if(!matches.get(key)!.some(m => m.source === c.source && m.matching_source === c.matching_source)) matches.get(key)!.push(c);
 }
 const ordered = [...groups].sort((a,b) => b[1].matches.size - a[1].matches.size || a[1].target.localeCompare(b[1].target));
 return <div className="entity-results"><section className="panel"><div className="entity-summary"><div><small>COMPARISON COVERAGE</small><h2>{data.indexed_investigations || 0} / {data.total_investigations || 0} investigations indexed</h2><p>Selected investigation: <strong>{data.index_status?.status || 'pending'}</strong></p></div><div><small>RESULTS SHOWN</small><h2>{groups.size} potential matches</h2><p>Grouped by investigation</p></div></div><p>{data.index_status?.detail}</p></section>
 <section className="panel"><h2>Applications with shared identifiers</h2><p>Each card shows another investigation containing the same identifier. Open both source references and confirm that the identifier belongs to each application before concluding they are related.</p><label className="entity-toggle"><input type="checkbox" checked={showDomains} onChange={e => setShowDomains(e.target.checked)}/>Include weak source-domain matches ({domainCount} evidence pairs)</label>
 {!ordered.length && <div className="entity-empty"><h3>No identifier matches to show</h3><p>{data.index_status?.status === 'completed' ? 'No shared contact, payment or social identifiers were found in the indexed evidence. This does not establish that the application is unrelated.' : 'Indexing is still pending or incomplete. Results update automatically.'}</p>{domainCount > 0 && <p>Source-domain matches are hidden because using the same platform, such as TikTok, does not establish a relationship.</p>}</div>}
 <div className="entity-related-list">{ordered.map(([investigationId, group]) => <article className="entity-related" key={investigationId}><header><div><small>POTENTIALLY RELATED INVESTIGATION</small><h3>{group.target}</h3><span>{group.matches.size} distinct shared identifiers · {investigationId}</span></div><Link className="button secondary" to={'/investigations/' + investigationId}>Open investigation →</Link></header>
 {[...group.matches].map(([key, matches]) => {const m = matches[0]; return <div className="entity-match" key={key}><div className="entity-match-heading"><span className={'entity-label ' + (m.kind === 'domain' ? 'weak' : '')}>{labels[m.kind] || m.kind}</span><strong>{m.value}</strong></div><p>{m.kind === 'domain' ? 'Weak association: both investigations reference this domain.' : m.kind === 'social' ? 'Shared social URL: verify it is a specific account belonging to both applications.' : 'Exact value found in both investigations; ownership and relevance need analyst review.'}</p><details><summary>Compare evidence from both investigations · {matches.length} source pairs</summary>{matches.map((pair, i) => <div key={i} className="entity-source-pair"><div><small>SELECTED APPLICATION’S EVIDENCE</small><SourceLink value={pair.matching_source}/></div><div><small>{group.target} — EVIDENCE</small><SourceLink value={pair.source}/></div>{pair.source === pair.matching_source && <p className="entity-shared-notice">Both investigations collected the same page. This is a repeated source, not independent confirmation.</p>}</div>)}</details></div>;})}</article>)}</div></section>
 <ExtractionDetails items={data.extractions}/></div>;
}
export function EntityDemoPage() {
 const [id, setId] = useState('');
 const [search, setSearch] = useState('');
 const query = useQuery({queryKey: ['entity-investigations'], queryFn: async () => {const r = await fetch('/api/v1/entities/investigations'); if(!r.ok) throw new Error('Unable to load investigations'); return r.json() as Promise<{id: string; target: string}[]>;}});
 const matches = query.data?.filter(r => (r.target + ' ' + r.id).toLowerCase().includes(search.trim().toLowerCase())) || [];
 const selected = query.data?.find(r => r.id === id);
 return <><PageHeader eyebrow="Across your investigation history" title="Entity discovery" description="Find an application, select its investigation, and compare shared identifiers with your investigation history."/>
 <section className="panel entity-picker"><label htmlFor="entity-search">Find an application</label><input id="entity-search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Type a name or URL, e.g. rana" autoComplete="off"/>{query.isLoading && <Loading/>}{query.error && <ErrorState error={query.error}/>}
 {!query.isLoading && !query.error && <><p role="status">{matches.length} matching investigations{!search.trim() ? ' · Type to narrow the list' : ''}</p><div className="entity-search-results" aria-label="Matching investigations">{matches.map(r => <button key={r.id} aria-pressed={id === r.id} onClick={() => setId(r.id)}><span><strong>{r.target}</strong><small>{r.id}</small></span><span>{id === r.id ? 'Selected ✓' : 'Compare →'}</span></button>)}</div>{!matches.length && <p>No completed investigations match “{search}”. Try part of the domain or investigation ID.</p>}</>}
 </section>{selected ? <><section className="entity-selected"><span>Comparing</span><strong>{selected.target}</strong><span>against all indexed investigations</span></section><EnrichmentResults key={id} id={id}/></> : <section className="panel"><h2>Select an application above</h2><p>Matching applications appear as you type. Click a result to see shared identifiers, the other investigations, and the evidence supporting each match.</p></section>}</>;
}
