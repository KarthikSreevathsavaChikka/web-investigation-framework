import unittest
from unittest.mock import Mock

from osint.models import NormalizedTarget, SearchResult
from osint.relevance import assess_serp_result, assess_page_relevance, target_keyword_proximity, build_target_variants
from osint.resolver import ResolutionProviderUnavailable, TargetResolver
from osint.search import AggregatingSearchProvider, SearchProvider
from osint.source_classifier import SourceClassifier
from osint.url_tools import normalize_result_url, registrable_domain


class FakeSearchProvider(SearchProvider):
    name = "fake"

    @property
    def available(self):
        return True

    def search(self, query: str, *, query_id: str, count: int):
        return [
            SearchResult(query_id, query, self.name, 1, "ExampleBet official betting", "https://www.examplebet.com/login", "Official sportsbook"),
            SearchResult(query_id, query, self.name, 2, "ExampleBet review", "https://reviews.test/examplebet", "Casino review"),
        ]


class RateLimitedSearchProvider(SearchProvider):
    name = "rate_limited"

    @property
    def available(self):
        return True

    def search(self, query: str, *, query_id: str, count: int):
        raise RuntimeError("Google rate-limited the public search request")


class StaticSearchProvider(SearchProvider):
    def __init__(self, name, results, available=True):
        self.name, self.results, self._available = name, results, available

    @property
    def available(self):
        return self._available

    def search(self, query: str, *, query_id: str, count: int):
        return [SearchResult(query_id, query, self.name, rank, title, url, snippet)
                for rank, (title, url, snippet) in enumerate(self.results, 1)]


class TargetResolverTests(unittest.TestCase):
    def test_classifies_supported_inputs(self):
        resolver = TargetResolver()
        self.assertEqual(resolver.classify("https://example.com/path"), "url")
        self.assertEqual(resolver.classify("example.com"), "domain")
        self.assertEqual(resolver.classify("example123"), "partial_name")
        self.assertEqual(resolver.classify("Example Bet"), "brand_or_app_name")

    def test_direct_domain_resolves_without_search(self):
        resolution = TargetResolver().resolve("https://www.example.com/path")
        self.assertEqual(resolution.candidates[0].domain, "example.com")
        self.assertEqual(resolution.candidates[0].confidence, 1.0)

    def test_derives_parent_brand_from_mirror_style_domain(self):
        resolution = TargetResolver().resolve("parimatchs123.com")
        self.assertEqual(resolution.resolved_brand, "Parimatch")

    def test_rate_limited_brand_resolution_returns_controlled_error(self):
        with self.assertRaisesRegex(ResolutionProviderUnavailable, "rate-limited"):
            TargetResolver().resolve("Tashanwin", RateLimitedSearchProvider())

    def test_brand_resolution_ranks_repeated_official_domain(self):
        resolution = TargetResolver().resolve("ExampleBet", FakeSearchProvider())
        self.assertEqual(resolution.candidates[0].domain, "examplebet.com")
        self.assertGreater(resolution.candidates[0].confidence, 0.7)

    def test_search_engine_domains_cannot_become_target_candidates(self):
        results = [
            SearchResult("R", "1xbet", "fake", 1, "1xbet official help", "https://support.google.com/chrome", "Official 1xbet app"),
            SearchResult("R", "1xbet", "fake", 2, "1xbet official", "https://1xbet.com", "Official betting"),
        ]
        candidates = TargetResolver().rank_candidates("1xbet", results)
        self.assertEqual([item.domain for item in candidates], ["1xbet.com"])

    def test_resolution_is_not_truncated_to_eight_candidates(self):
        results = [
            SearchResult("R", "ExampleBet", "fake", index, "ExampleBet official site", f"https://examplebet-{index}.test", "Official betting")
            for index in range(1, 13)
        ]
        self.assertEqual(len(TargetResolver().rank_candidates("ExampleBet", results)), 12)

    def test_aggregates_distinct_domains_from_all_available_providers(self):
        first = StaticSearchProvider("first", [("ExampleBet", "https://examplebet.com", "Official")])
        second = StaticSearchProvider("second", [
            ("ExampleBet", "https://examplebet.com/?utm_source=second", "Official"),
            ("ExampleBet India", "https://examplebet-india.com", "Official betting"),
        ])
        results = AggregatingSearchProvider([first, second]).search("ExampleBet", query_id="R", count=20)
        self.assertEqual({item.url for item in results}, {"https://examplebet.com", "https://examplebet-india.com"})

    def test_aggregator_records_each_provider_outcome_when_one_fails(self):
        successful = StaticSearchProvider(
            "successful",
            [("ExampleBet", "https://examplebet.com", "Official")],
        )
        provider = AggregatingSearchProvider([successful, RateLimitedSearchProvider()])

        results = provider.search("ExampleBet", query_id="R", count=20)
        reports = provider.execution_reports("R")

        self.assertEqual(len(results), 1)
        self.assertEqual(
            [(item.provider, item.status) for item in reports],
            [("successful", "completed"), ("rate_limited", "failed")],
        )
        self.assertIn("rate-limited", reports[1].error)

    def test_aggregator_skips_a_provider_after_its_first_failure(self):
        successful = StaticSearchProvider(
            "successful",
            [("ExampleBet", "https://examplebet.com", "Official")],
        )
        failed = RateLimitedSearchProvider()
        failed.search = Mock(side_effect=RuntimeError("timed out"))
        provider = AggregatingSearchProvider([successful, failed])

        provider.search("ExampleBet", query_id="R1", count=20)
        provider.search("ExampleBet official", query_id="R2", count=20)

        self.assertEqual(failed.search.call_count, 1)
        second_reports = provider.execution_reports("R2")
        self.assertIn("Skipped after an earlier provider failure", second_reports[1].error)

    def test_aggregator_distinguishes_all_failed_from_no_results(self):
        provider = AggregatingSearchProvider([RateLimitedSearchProvider()])

        with self.assertRaisesRegex(RuntimeError, "rate_limited"):
            provider.search("ExampleBet", query_id="R", count=20)

        self.assertEqual(provider.execution_reports("R")[0].status, "failed")

    def test_rejects_fuzzy_unrelated_domain_candidates(self):
        results = [
            SearchResult("R1", "Puntit", "fake", 1, "YouTube Kids", "https://youtubekids.com/", "Safe videos for children"),
            SearchResult("R2", "Puntit", "fake", 2, "Puntit review", "https://reviews.test/puntit", "casino review"),
        ]
        self.assertEqual(TargetResolver().rank_candidates("Puntit", results), [])

    def test_preserves_short_numeric_brand(self):
        self.assertEqual(TargetResolver.derive_main_brand("fun88"), "Fun88")

    def test_builds_only_conservative_search_identities(self):
        target = NormalizedTarget("parimatchs123.com", "parimatchs123.com", "https://parimatchs123.com", "Parimatchs123")
        identities = TargetResolver.build_search_identities(target)
        values = {item.value.casefold() for item in identities}
        self.assertIn("parimatchs123.com", values)
        self.assertIn("parimatchs123", values)
        self.assertIn("parimatchs 123", values)
        self.assertIn("parimatch", values)


class URLAndSourceTests(unittest.TestCase):
    def test_normalizes_tracking_and_fragment(self):
        normalized = normalize_result_url("HTTPS://News.Example/a/?utm_source=x&id=2#section")
        self.assertEqual(normalized, "https://news.example/a?id=2")

    def test_handles_multi_label_public_suffix(self):
        self.assertEqual(registrable_domain("sub.example.co.uk"), "example.co.uk")

    def test_classifies_target_social_and_documents(self):
        self.assertEqual(SourceClassifier.classify("https://app.example.com/login", "example.com"), "target_subdomain")
        self.assertEqual(SourceClassifier.classify("https://x.com/example", "example.com"), "social_x")
        self.assertEqual(SourceClassifier.classify("https://other.test/report.pdf", "example.com"), "pdf_document")

    def test_rejects_generic_keyword_search_noise(self):
        target = NormalizedTarget("parimatchs123.com", "parimatchs123.com", "https://parimatchs123.com", "Parimatchs123")
        unrelated = SearchResult("Q001", "deposit", "bing_rss", 1, "Deposit definition", "https://investopedia.com/deposit", "A deposit is money")
        accepted = SearchResult("Q001", "deposit", "bing_rss", 1, "Parimatchs123 withdrawal complaint", "https://reviews.example/report", "Parimatchs123 withdrawal pending")
        self.assertFalse(assess_serp_result(unrelated, target).accepted)
        self.assertTrue(assess_serp_result(accepted, target).accepted)

    def test_requires_target_and_keyword_proximity(self):
        variants = build_target_variants(NormalizedTarget("example.com", "example.com", "https://example.com", "Example"))
        self.assertIsNotNone(target_keyword_proximity("Example withdrawal pending", variants, ["withdrawal"]))
        self.assertIsNone(target_keyword_proximity("Example footer " + "x" * 600 + "withdrawal", variants, ["withdrawal"]))

    def test_page_level_target_validation(self):
        target = NormalizedTarget("parimatch.com", "parimatch.com", "https://parimatch.com", "Parimatch")
        accepted = assess_page_relevance(
            target=target,
            visible_text="Users report Parimatch withdrawal pending.",
            final_url="https://reviews.test/report",
        )
        rejected = assess_page_relevance(
            target=target,
            visible_text="Paytm supports UPI deposits.",
            final_url="https://payments.test/upi",
        )
        self.assertTrue(accepted.accepted)
        self.assertFalse(rejected.accepted)


if __name__ == "__main__":
    unittest.main()
