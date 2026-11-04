import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from osint.llm_review import RelevanceReviewer, review_source, select_passages
from osint.models import NormalizedTarget, Observation
from osint.target_profile import build_target_profile, extract_profile_observations, profile_reference_terms
from scripts.benchmark_relevance_review import DEFAULT_CASES, evaluate, prepare_case, summarize


class TargetProfileTests(unittest.TestCase):
    def setUp(self):
        self.target = NormalizedTarget("nova-play.example", "nova-play.example", "https://nova-play.example", "Nova Play")

    def test_explicit_page_metadata_has_provenance_without_ownership(self):
        html = '''<html lang="es-ES"><head><title>Guessed unrelated title</title>
        <meta property="og:site_name" content="Nova Juego">
        <script type="application/ld+json">{
          "@graph": [
            {"@type":"Organization", "url":"https://nova-play.example", "legalName":"Nova Operations Ltd", "alternateName":"Nova Games"},
            {"@type":"Organization", "url":"https://other.example", "alternateName":"Foreign Brand"},
            {"@type":"Article", "author":{"@type":"Organization","name":"Independent Reporter"}}
          ]}</script></head></html>'''
        observations = extract_profile_observations(html, "https://nova-play.example/about")
        profile = build_target_profile(self.target, observations)
        self.assertEqual({f["value"] for f in profile["aliases"]}, {"Nova Juego", "Nova Games"})
        self.assertEqual([f["value"] for f in profile["organizations"]], ["Nova Operations Ltd"])
        self.assertEqual(profile["languages"][0]["value"], "es-ES")
        self.assertEqual(profile["operators"], [])  # legalName alone does not assert operator status.
        for kind in ("aliases", "organizations", "languages"):
            for fact in profile[kind]:
                self.assertFalse(fact["ownership_verified"])
                self.assertTrue(fact["evidence_field"])
                self.assertEqual(fact["evidence_text"], fact["value"])
                self.assertEqual(fact["source_url"], "https://nova-play.example/about")
        self.assertNotIn("Independent Reporter", json.dumps(profile))
        self.assertNotIn("Guessed unrelated title", json.dumps(profile))

    def test_observed_social_links_accept_storage_dicts_and_reject_off_target_claims(self):
        social = {"id": 7, "collector": "public_web", "entity_type": "SOCIAL_PROFILE",
                  "value": "https://x.com/nova_help", "source_url": "https://nova-play.example/contact",
                  "metadata_json": json.dumps({"platform": "X"})}
        off_target = {"collector": "search", "entity_type": "BRAND_ALIAS", "value": "Comet Club",
                      "source_url": "https://nova-play.example.evil.example", "metadata": {"evidence_field": "title"}}
        guess = Observation("search", "Identity", "BRAND_ALIAS", "Made Up Alias", "https://nova-play.example")
        profile = build_target_profile(self.target, [social, social, off_target, guess])
        self.assertEqual(len(profile["social_accounts"]), 1)
        self.assertEqual(profile["social_accounts"][0]["observation_id"], 7)
        self.assertEqual(profile["social_accounts"][0]["association"], "website_linked")
        self.assertEqual(profile["aliases"], [])
        self.assertNotIn("Comet Club", profile_reference_terms(self.target, profile))

    def test_profile_facts_are_bounded_and_broken_metadata_is_ignored(self):
        observations = [Observation("public_web", "Identity", "BRAND_ALIAS", "Name " + str(i), self.target.url,
                                    metadata={"evidence_field": "meta:og:site_name"}) for i in range(80)]
        observations.append({"entity_type": "BRAND_ALIAS", "value": "Invalid", "source_url": self.target.url,
                             "metadata_json": "[]"})
        profile = build_target_profile(self.target, observations)
        self.assertEqual(len(profile["aliases"]), 20)

    def test_malformed_jsonld_does_not_break_collector(self):
        for payload in ('bad json', 'null', '42', '{"@type":42}', '{"@graph":"not a list"}'):
            self.assertEqual(extract_profile_observations('<script type="application/ld+json">' + payload + '</script>', self.target.url), [])


class TargetPassageTests(unittest.TestCase):
    target = NormalizedTarget("nova-play.example", "nova-play.example", "https://nova-play.example", "Nova Play")

    def assert_exact_bounded(self, source, original):
        self.assertLessEqual(source["selected_text_length"], 6000)
        self.assertEqual(source["original_text_length"], len(original))
        self.assertEqual(source["original_text_sha256"], hashlib.sha256(original.encode()).hexdigest())
        last_end = 0
        for passage in source["passages"]:
            self.assertGreaterEqual(passage["start"], last_end)
            self.assertEqual(passage["text"], original[passage["start"]:passage["end"]])
            last_end = passage["end"]

    def test_late_reference_keeps_original_offsets_and_surrounding_context(self):
        text = "Equipment records.\n" * 800 + "Prior context. Nova Play at nova-play.example: withdrawal issue. Following context."
        source = review_source("https://records.example/case", "Case", text, kind="document", source_ref="1", target=self.target)
        self.assert_exact_bounded(source, text)
        excerpts = "\n".join(p["text"] for p in source["passages"])
        self.assertIn("Prior context. Nova Play at nova-play.example: withdrawal issue. Following context.", excerpts)
        self.assertEqual(source["passage_selection"], "target_references")
        self.assertTrue(source["truncated"])

    def test_case_insensitive_unicode_references_preserve_exact_text(self):
        profile = build_target_profile(self.target, [Observation("public_web", "Identity", "BRAND_ALIAS", "诺瓦游戏", self.target.url,
                  metadata={"evidence_field": "meta:og:site_name"})])
        text = "Unrelated material. " * 700 + "我在诺瓦游戏平台申请提款。"
        source = review_source("https://forum.example/p", "", text, kind="page", source_ref="1", target=self.target, profile=profile)
        self.assert_exact_bounded(source, text)
        self.assertTrue(any("我在诺瓦游戏平台申请提款。" in p["text"] for p in source["passages"]))

    def test_substrings_do_not_become_reference_matches(self):
        target = NormalizedTarget("nova.example", "nova.example", "https://nova.example", "Nova")
        passages, method = select_passages("Innovation and innovative engineering. " * 400, target=target)
        self.assertEqual(method, "distributed_context")
        self.assertGreater(passages[-1]["start"], 6000)

    def test_repeated_mentions_and_end_boundary_remain_bounded(self):
        text = ("Nova Play " + "x" * 1300 + "\n") * 30 + "nova-play.example FINAL WITHDRAWAL CONTEXT"
        source = review_source("https://forum.example/p", "", text, kind="page", source_ref="1", target=self.target)
        self.assert_exact_bounded(source, text)
        self.assertTrue(any("FINAL WITHDRAWAL CONTEXT" in p["text"] for p in source["passages"]))

    @patch("osint.llm_review.requests.post")
    def test_profile_survives_request_success_and_unavailable_records(self, post):
        profile = build_target_profile(self.target)
        source = review_source(self.target.url, "", "Nova Play payment rules", kind="page", source_ref="1", target=self.target)
        answer = {"relevance": "relevant", "relationship": "first_party_claim", "passage_ids": [1],
                  "categories": ["payment"], "reason": "Target-specific text.", "candidate_links": []}
        response = Mock(status_code=200)
        response.json.return_value = {"choices": [{"message": {"content": json.dumps(answer)}}]}
        post.return_value = response
        reviewer = RelevanceReviewer()
        success = reviewer.run(self.target, [source], stage="content", profile=profile)
        sent = json.loads(post.call_args.kwargs["json"]["messages"][1]["content"])
        self.assertEqual(sent["target_profile"], profile)
        self.assertEqual(success.observations[0].metadata["review_input"], sent)
        post.side_effect = TimeoutError
        unavailable = reviewer.run(self.target, [source], stage="content", profile=profile)
        self.assertEqual(unavailable.observations[0].metadata["review_input"], sent)
        self.assertEqual(unavailable.observations[0].metadata["input_sha256"], success.observations[0].metadata["input_sha256"])


class RelevanceBenchmarkTests(unittest.TestCase):
    def test_all_seed_cases_validate_without_network_and_select_late_evidence(self):
        cases = json.loads(DEFAULT_CASES.read_text())
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        self.assertGreaterEqual(len(cases), 30)
        with patch("osint.llm_review.requests.post", side_effect=AssertionError("Offline benchmark must not call server")):
            result = evaluate(cases)
        self.assertEqual(result["metrics"]["attempted"], 0)
        self.assertIsNone(result["metrics"]["accuracy_on_valid_reviews"])
        late = next(row for row in result["cases"] if row["id"] == "late-document-reference")
        self.assertTrue(any("Appendix 9:" in p["text"] for p in late["source"]["passages"]))
        for case in cases:
            prepare_case(case)

    def test_metrics_include_abstentions_failures_and_unreviewed_positive_cases(self):
        rows = [dict(expected="relevant", prediction="relevant"), dict(expected="unrelated", prediction="relevant"),
                dict(expected="relevant", prediction="uncertain"), dict(expected="relevant", prediction="unavailable"),
                dict(expected="relevant", prediction="not_run"), dict(expected="unrelated", prediction="unrelated")]
        metrics = summarize(rows)
        self.assertEqual(metrics["relevant_precision"], 0.5)
        self.assertEqual(metrics["relevant_recall_including_unavailable_and_unreviewed"], 0.25)
        self.assertEqual(metrics["availability"], 0.8)
        self.assertEqual(metrics["accuracy_on_valid_reviews"], 0.5)

    def test_live_outage_stops_inference_and_reports_remaining_not_run(self):
        cases = json.loads(DEFAULT_CASES.read_text())[:5]
        reviewer = Mock(timeout=1, model="mock")
        reviewer.review.side_effect = TimeoutError
        result = evaluate(cases, live=True, seconds=10, reviewer=reviewer)
        self.assertEqual(reviewer.review.call_count, 2)
        self.assertEqual([row["prediction"] for row in result["cases"]], ["unavailable"] * 2 + ["not_run"] * 3)
        self.assertEqual(result["metrics"]["availability"], 0.0)
