import { useState } from 'react';
import { formatDate } from '../components';
type Row = Record<string, unknown>;
const text = (v: unknown) => v === null || v === undefined ? '' : String(v);
export function ScreenshotGallery({rows}: {rows: Row[]}) {
 const [similar, setSimilar] = useState(true);
 const groups = new Map<string, Map<string, Row[]>>();
 rows.forEach((row, index) => {
  const identity = text(row.screenshot_identity) || `record-${index}`;
  const group = similar ? text(row.screenshot_group) || identity : identity;
  if(!groups.has(group)) groups.set(group, new Map());
  const variants = groups.get(group)!;
  if(!variants.has(identity)) variants.set(identity, []);
  variants.get(identity)!.push(row);
 });
 const unique = new Set(rows.map((r,i) => text(r.screenshot_identity) || `record-${i}`)).size;
 return <div className="result-list"><section className="panel"><h2>Screenshot evidence</h2><p>{rows.length} capture references · {unique} unique images · {groups.size} displayed groups</p><label><input type="checkbox" checked={similar} onChange={e => setSimilar(e.target.checked)}/> Group visually similar captures from the same page</label><p>Exact duplicates share one image. Similar variants may contain meaningful differences; expand them to compare. Original evidence is retained.</p></section>{[...groups].map(([key, variants]) => {
 const entries = [...variants.values()];
 return <article className="result-card evidence-card" key={key}><h3>{text(entries[0][0].page_title || entries[0][0].title || entries[0][0].query_name) || 'Captured evidence'}</h3><Capture rows={entries[0]}/>{entries.length > 1 && <details className="screenshot-variants"><summary>Show {entries.length - 1} visually similar variants — review differences</summary>{entries.slice(1).map((v,i) => <Capture key={i} rows={v}/>)}</details>}</article>;
 })}{!rows.length && <section className="panel">No screenshot evidence available.</section>}</div>;
}
function Capture({rows}: {rows: Row[]}) {
 const first = rows[0];
 return <section>{!!first.screenshot_url && <a href={text(first.screenshot_url)} target="_blank" rel="noreferrer"><img src={text(first.screenshot_url)} alt={text(first.page_title || first.title) || 'Evidence capture'} loading="lazy"/></a>}{!!first.screenshot_summary && <div className="screenshot-summary"><strong>Screenshot summary</strong><p>{text(first.screenshot_summary)}</p></div>}<details open={rows.length === 1}><summary>{rows.length} evidence reference{rows.length === 1 ? '' : 's'} supporting this image</summary>{rows.map((r,i) => <div className="screenshot-reference" key={i}><strong>{text(r.query_name || r.title || r.platform) || 'Evidence finding'}</strong><small>Evidence ID: {text(r.id)} · Query: {text(r.query_id) || 'Not supplied'} · Captured: {r.captured_at ? formatDate(text(r.captured_at)) : 'Not supplied'}</small><p>{text(r.context_text || r.evidence_text || r.post_text || r.search_snippet)}</p>{/^https?:\/\//i.test(text(r.source_url || r.post_url)) && <a href={text(r.source_url || r.post_url)} target="_blank" rel="noreferrer">{text(r.source_url || r.post_url)} ↗</a>}</div>)}</details></section>;
}
