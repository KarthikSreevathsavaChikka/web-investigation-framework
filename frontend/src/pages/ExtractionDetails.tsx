import { useState } from 'react';
export type Extraction = {id: string; source: string; result: {status: string; error?: string; text?: string; pages?: {page: number; text?: string; qr_contents: string}[]}};
const navigation = /^(home|shorts|subscriptions|history|sign in|sign up|log in|explore|show more|youtube premium|youtube music|youtube kids|youtube labs|report history|settings|search|playlists|preview channel)$/i;
export function readableLines(text: string) {
 return text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !navigation.test(line));
}
function sourceName(source: string) {
 try {const url = new URL(source); return url.hostname.replace(/^www\./, '') + (url.pathname === '/' ? '' : url.pathname);}
 catch {return source || 'Source unavailable';}
}
function Artifact({item, index}: {item: Extraction; index: number}) {
 const [raw, setRaw] = useState(false);
 const pages = item.result.pages?.length ? item.result.pages : [{page: 1, text: item.result.text || '', qr_contents: ''}];
 const text = item.result.text || pages.map(p => p.text || '').join('\n');
 const emails = [...new Set(text.match(/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/g) || [])];
 const qr = pages.filter(p => p.qr_contents);
 const completed = item.result.status === 'completed';
 return <article className="ocr-card"><header><span className="ocr-number">{String(index + 1).padStart(2, '0')}</span><div><h3>{sourceName(item.source)}</h3><span>Artifact {index + 1} · {pages.length} page{pages.length === 1 ? '' : 's'}</span></div><span className={'ocr-badge ' + (completed ? 'done' : 'issue')}>{completed ? 'Text extraction finished' : item.result.status.replaceAll('_', ' ')}</span></header>
 <div className="ocr-card-body"><div className="ocr-assessment"><strong>Relevance to the investigated application: not assessed here</strong><p>This is text read from a capture. A matching name, channel title or search page does not establish a connection to the application.</p></div>
 {/^https?:\/\//i.test(item.source) && <a className="ocr-source" href={item.source} target="_blank" rel="noreferrer">Open source page ↗</a>}
 {!completed && <p role="status">{item.result.error || 'Extraction did not complete. No conclusion can be drawn from missing text or QR results.'}</p>}
 <div className="ocr-facts"><section><h4>Email addresses in OCR</h4>{emails.length ? emails.map(e => <code key={e}>{e}</code>) : <p>No email address recognized in the extracted text.</p>}<small>Recognized values require checking against the capture.</small></section><section><h4>QR decoding</h4>{qr.length ? qr.map(p => <div key={p.page}><small>Page {p.page} · decoded contents</small><code>{p.qr_contents}</code></div>) : <p>{completed ? 'No QR contents decoded. This does not confirm the absence of a QR code.' : 'No successful QR result available.'}</p>}</section></div>
 <div className="ocr-text-heading"><h4>{raw ? 'Original OCR output' : 'Readable OCR text'}</h4><button type="button" className="button secondary" aria-pressed={raw} onClick={() => setRaw(!raw)}>{raw ? 'Show readable text' : 'Show raw OCR'}</button></div>
 <p className="ocr-help">{raw ? 'Unmodified extraction output, including recognition errors.' : 'Blank lines and common standalone menu labels are omitted. Wording and recognition errors are preserved; this is not a summary.'}</p>
 {raw ? <pre className="ocr-raw">{text || 'No text extracted.'}</pre> : pages.map(p => {const lines = readableLines(p.text || (pages.length === 1 ? text : '')); return <section className="ocr-page" key={p.page}><h5>Page {p.page}</h5>{lines.length ? lines.map((line,i) => <p key={i}>{line}</p>) : <p>No readable text available on this page.</p>}</section>;})}
 </div></article>;
}
export function ExtractionDetails({items}: {items: Extraction[]}) {
 const completed = items.filter(i => i.result.status === 'completed').length;
 const qr = items.filter(i => i.result.pages?.some(p => p.qr_contents)).length;
 return <section className="panel ocr-workspace"><h2>OCR and QR evidence</h2><p>Inspect what was read from each capture and distinguish extracted text from verified findings.</p><div className="ocr-stats"><div><strong>{items.length}</strong><span>Artifacts processed</span></div><div><strong>{completed}</strong><span>Extractions finished</span></div><div><strong>{qr}</strong><span>Artifacts with decoded QR contents</span></div></div>{!items.length && <p>Extraction results will appear here when background processing completes.</p>}<div className="ocr-artifacts">{items.map((item,i) => <Artifact key={item.id} item={item} index={i}/>)}</div></section>;
}
