"""Source-backed comparison and entity associations for linked investigations."""
from urllib.parse import urlsplit


def compare_records(before, after):
    def index(rows):
        return {str(r.get('domain') or r.get('source_url') or r.get('url') or r.get('indicator') or r.get('name')): r for r in rows}
    old, new = index(before), index(after)
    return {'added': [new[k] for k in sorted(new.keys() - old.keys())],
            'removed': [old[k] for k in sorted(old.keys() - new.keys())],
            'retained': sorted(old.keys() & new.keys())}


def entity_graph(investigations):
    nodes, edges = {}, []
    for investigation_id, sources in investigations:
        nodes[investigation_id] = {'id': investigation_id, 'type': 'investigation'}
        for source in sources:
            url = source.get('source_url') or source.get('url') or ''
            domain = urlsplit(url).hostname
            if domain:
                nodes[domain] = {'id': domain, 'type': 'domain'}
                edges.append({'from': investigation_id, 'to': domain, 'source_url': url, 'relationship': 'collected source'})
    return {'nodes': list(nodes.values()), 'edges': edges}
