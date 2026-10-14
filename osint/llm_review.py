"""Bounded, advisory-only LM Studio review of stored/discovered text."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from urllib.parse import urlsplit

import requests

from config import BASE_DIR
from osint.cancellation import InvestigationCancelled
from osint.models import CollectorResult, Observation
from osint.target_profile import build_target_profile, profile_reference_terms

PROMPT_VERSION = 'target-relevance-v3'
RELATIONSHIPS = {'first_party_claim', 'third_party_discussion', 'promotion', 'complaint',
                 'incidental_mention', 'possible_impersonation', 'unknown'}
CATEGORIES = {'identity', 'payment', 'gambling_activity', 'promotion', 'complaint',
              'application', 'contact', 'document', 'other'}
FIELDS = {'relevance', 'relationship', 'passage_ids', 'categories', 'reason', 'candidate_links'}


def response_format(source):
    """Constrain syntax at generation time; semantic checks still run locally."""
    schema = {
        'type': 'object', 'additionalProperties': False, 'required': sorted(FIELDS),
        'properties': {
            'relevance': {'type': 'string', 'enum': ['relevant', 'unrelated', 'uncertain']},
            'relationship': {'type': 'string', 'enum': sorted(RELATIONSHIPS)},
            'passage_ids': {'type': 'array', 'items': {'type': 'integer', 'enum': [p['id'] for p in source['passages']]}},
            'categories': {'type': 'array', 'items': {'type': 'string', 'enum': sorted(CATEGORIES)}},
            'reason': {'type': 'string', 'minLength': 1, 'maxLength': 1500},
            'candidate_links': {'type': 'array', 'items': {'type': 'string'}},
        },
    }
    if source['candidate_links']:
        schema['properties']['candidate_links']['items']['enum'] = source['candidate_links']
    else:
        schema['properties']['candidate_links']['maxItems'] = 0
    return {'type': 'json_schema', 'json_schema': {'name': 'target_relevance', 'strict': True, 'schema': schema}}


def validate_review(value, source):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Invalid review fields')
    if value['relevance'] not in {'relevant', 'unrelated', 'uncertain'} or value['relationship'] not in RELATIONSHIPS:
        raise ValueError('Invalid relevance or relationship')
    ids = value['passage_ids']
    valid_ids = {p['id'] for p in source['passages']}
    if not isinstance(ids, list) or any(type(i) is not int or i not in valid_ids for i in ids):
        raise ValueError('Review cites an unknown passage')
    if value['relevance'] == 'relevant' and not ids:
        raise ValueError('Relevant verdict has no supporting passage')
    for field, allowed in [('categories', CATEGORIES), ('candidate_links', set(source['candidate_links']))]:
        if not isinstance(value[field], list) or any(not isinstance(x, str) or x not in allowed for x in value[field]):
            raise ValueError(f'Invalid {field}')
    if not isinstance(value['reason'], str) or not 1 <= len(value['reason']) <= 1500:
        raise ValueError('Invalid explanation')
    return value


def _evenly_spaced(values, limit):
    if len(values) <= limit:
        return values
    if limit == 1:
        return values[:1]
    return [values[round(i * (len(values) - 1) / (limit - 1))] for i in range(limit)]


def select_passages(text, *, target=None, profile=None):
    """Choose exact, non-overlapping excerpts with offsets into the supplied text.

    Keep opening context and spread target-reference windows across long input.
    Text with no references is sampled across its length. Callers without target
    information retain the previous leading-context behavior.
    """
    limit, width = 6000, 1000
    terms = profile_reference_terms(target, profile)
    method = 'leading_context'
    if len(text) <= limit or not terms:
        ranges = [(start, min(start + width, len(text))) for start in range(0, min(len(text), limit), width)]
    else:
        ranges = [(0, width)]
        hits = set()
        for term in terms:
            # Unicode CJK names may occur without spaces; other names use word
            # boundaries so e.g. "Nova" does not match "Innovation".
            cjk = any('\u3400' <= c <= '\u9fff' or '\u3040' <= c <= '\u30ff' for c in term)
            pattern = re.escape(term) if cjk else r'(?<!\w)' + re.escape(term) + r'(?!\w)'
            buckets = {}
            last_match = None
            for match in re.finditer(pattern, text, re.IGNORECASE):
                buckets.setdefault(min(39, match.start() * 40 // len(text)), match.start())
                last_match = match.start()
            # Evenly sample repeated navigation mentions; preserve late references.
            hits.update(buckets.values())
            if last_match is not None:
                hits.add(last_match)
        candidates = []
        last_end = width
        for hit in sorted(hits):
            start = max(width, min(hit - 400, len(text) - width))
            if hit < last_end:
                continue
            start = max(start, last_end)
            candidates.append((start, min(start + width, len(text))))
            last_end = start + width
        if candidates:
            ranges.extend(_evenly_spaced(candidates, 5))
            method = 'target_references'
        else:
            method = 'distributed_context'
        if len(ranges) < 6:
            fillers = []
            for start in _evenly_spaced(range(width, len(text), width), 12):
                end = min(start + width, len(text))
                if not any(start < b and end > a for a, b in ranges):
                    fillers.append((start, end))
            ranges.extend(_evenly_spaced(fillers, 6 - len(ranges)))
        ranges.sort()
    return ([{'id': index + 1, 'start': start, 'end': end, 'text': text[start:end]}
             for index, (start, end) in enumerate(ranges)], method)


def review_source(source_url, title, text, *, kind, source_ref, target=None, profile=None):
    """Exact bounded excerpts: no generated text is ever used as source evidence."""
    if not isinstance(text, str) or not text.strip():
        return None
    passages, selection = select_passages(text, target=target, profile=profile)
    selected_length = sum(len(p['text']) for p in passages)
    return {'source_url': source_url, 'title': str(title or '')[:300], 'kind': kind,
            'source_ref': source_ref, 'passages': passages, 'truncated': len(text) > selected_length,
            'original_text_length': len(text), 'selected_text_length': selected_length,
            'original_text_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'passage_selection': selection,
            'candidate_links': [source_url] if urlsplit(source_url).scheme in {'http', 'https'} else []}


class RelevanceReviewer:
    def __init__(self):
        self.enabled = os.getenv('OSINT_LLM_REVIEW_ENABLED', 'false').lower() in {'1', 'true', 'yes'}
        self.url = os.getenv('LM_STUDIO_BASE_URL', 'http://10.244.1.54:1234').rstrip('/')
        if self.url.endswith('/v1'):
            self.url += '/chat/completions'
        elif not self.url.endswith('/v1/chat/completions'):
            self.url += '/v1/chat/completions'
        self.model = os.getenv('LM_STUDIO_MODEL', 'google/gemma-4-e4b')
        self.api_key = os.getenv('LM_STUDIO_API_KEY', '')
        self.timeout = max(1, min(float(os.getenv('OSINT_LLM_TIMEOUT', '15')), 60))
        self.budget = max(0, min(int(os.getenv('OSINT_LLM_REVIEW_BUDGET', '12')), 50))
        self.seconds = max(1, min(float(os.getenv('OSINT_LLM_STAGE_SECONDS', '60')), 300))
        self.prompt = (BASE_DIR / 'config' / 'relevance_review.txt').read_text()
        self.prompt_hash = hashlib.sha256(self.prompt.encode()).hexdigest()

    @staticmethod
    def request_input(target, source, profile=None):
        return {'target': {'url': target.url, 'domain': target.domain, 'brand': target.brand},
                'target_profile': profile if profile is not None else build_target_profile(target),
                'source': source}

    def review(self, target, source, timeout, *, profile=None):
        parsed = urlsplit(self.url)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Invalid LM Studio server address')
        request_input = self.request_input(target, source, profile)
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        response = requests.post(self.url, json={
            'model': self.model,
            'messages': [{'role': 'system', 'content': self.prompt},
                         {'role': 'user', 'content': json.dumps(request_input, ensure_ascii=False)}],
            'temperature': 0, 'max_tokens': 512, 'reasoning_effort': 'none', 'stream': False,
            'response_format': response_format(source),
        }, headers=headers, timeout=timeout, allow_redirects=False)
        try:
            if response.status_code != 200:
                raise ValueError(f'LM Studio HTTP {response.status_code}')
            payload = response.json()
            if payload['choices'][0].get('finish_reason') == 'length':
                raise ValueError('Model response exceeded output budget')
            answer = payload['choices'][0]['message']['content']
            decision = validate_review(json.loads(answer), source)
            return {**decision, 'model': self.model, 'returned_model': payload.get('model'),
                    'prompt_version': PROMPT_VERSION, 'prompt_sha256': self.prompt_hash,
                    'input_sha256': hashlib.sha256(json.dumps(request_input, sort_keys=True).encode()).hexdigest(),
                    'review_input': request_input, 'response_format': response_format(source),
                    'raw_response': answer, 'review_status': 'reviewed'}
        finally:
            response.close()

    def run(self, target, sources, *, stage, cancel_check=None, profile=None):
        started = time.monotonic()
        observations = []
        failures = 0
        seen = set()
        eligible = []
        for source in sources:
            if source is None:
                continue
            key = (source['source_url'], json.dumps(source['passages'], sort_keys=True))
            if key not in seen:
                eligible.append(source)
                seen.add(key)
        for source in eligible[:self.budget]:
            if cancel_check and cancel_check():
                raise InvestigationCancelled('Cancelled during advisory LLM review')
            remaining = self.seconds - (time.monotonic() - started)
            if remaining <= 0:
                break
            try:
                review = self.review(target, source, min(self.timeout, remaining), profile=profile)
            except Exception as exc:
                failures += 1
                review = {'relevance': 'uncertain', 'relationship': 'unknown', 'passage_ids': [],
                          'categories': [], 'candidate_links': [], 'reason': 'Model review unavailable; retain for review.',
                          'review_status': 'unavailable', 'error': str(exc)[:200] if isinstance(exc, ValueError) else type(exc).__name__,
                          'model': self.model, 'prompt_version': PROMPT_VERSION,
                          'prompt_sha256': self.prompt_hash, 'review_input': self.request_input(target, source, profile)}
                review['input_sha256'] = hashlib.sha256(json.dumps(review['review_input'], sort_keys=True).encode()).hexdigest()
            review['stage'] = stage
            observations.append(Observation('llm_relevance_' + stage, 'Advisory AI review', 'LLM_RELEVANCE_REVIEW',
                                            stage + ':' + source['source_ref'] + ':' + review['relevance'],
                                            source['source_url'], confidence=0.0, metadata=review))
            if failures >= 2:
                break  # A server outage must not stall the investigation.
        skipped = len(eligible) - len(observations)
        return CollectorResult('llm_relevance_' + stage, 'PARTIAL' if failures or skipped else 'COMPLETED',
                               observations, error=f'{len(observations)}/{len(eligible)} reviewed; {failures} unavailable; {skipped} outside budget or skipped.',
                               duration_seconds=time.monotonic() - started)


def collected_sources(repository, investigation_id, *, target=None, profile=None):
    """Interleave social, document and page excerpts so one type cannot consume the whole budget."""
    groups = {'documents': [], 'pages': []}
    for x in repository.get_social_findings(investigation_id):
        groups.setdefault('social:' + str(x.get('platform', 'unknown')), []).append(review_source(x['post_url'], x.get('title'), x.get('post_text'),
                                       kind='social_text', source_ref=f"social:{x['id']}", target=target, profile=profile))
    for x in repository.get_documents(investigation_id):
        groups['documents'].append(review_source(x['source_url'], x.get('file_name'), x.get('evidence_context'),
                                       kind='document_excerpt', source_ref=f"document:{x['id']}", target=target, profile=profile))
    for x in repository.get_evidence(investigation_id):
        groups['pages'].append(review_source(x['source_url'], x.get('page_title'), x.get('context_text') or x.get('evidence_text'),
                                       kind='page_excerpt', source_ref=f"evidence:{x['id']}", target=target, profile=profile))
    for x in repository.get_observations(investigation_id):
        if x['entity_type'] == 'PUBLIC_PAGE_EVIDENCE':
            groups['pages'].append(review_source(x['source_url'], x.get('source_title'), x.get('evidence_snippet'),
                                           kind='page_excerpt', source_ref=f"observation:{x['id']}", target=target, profile=profile))
    values = list(groups.values())
    return [group[i] for i in range(max(map(len, values), default=0)) for group in values if i < len(group)]
