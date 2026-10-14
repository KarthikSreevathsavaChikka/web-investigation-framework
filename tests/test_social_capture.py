import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from osint.cancellation import InvestigationCancelled
from osint.collectors.base import CollectorContext
from osint.collectors.social_capture import (
    AUTH_SELECTORS, enrich_social_findings, extract_post, install_navigation_guard,
    platform_url_allowed, post_identity, validate_social_page,
)
from osint.collectors.x_authenticated import XAuthenticatedCollector
from osint.models import NormalizedTarget, Observation


class Nodes:
    def __init__(self, nodes=()):
        self.nodes = list(nodes)

    async def count(self):
        return len(self.nodes)

    @property
    def first(self):
        return self.nodes[0]

    def nth(self, index):
        return self.nodes[index]

    async def inner_text(self, **kwargs):
        return await self.first.inner_text(**kwargs)


class Node:
    def __init__(self, text="", attrs=None, children=None):
        self.text = text
        self.attrs = attrs or {}
        self.children = children or {}

    def locator(self, selector):
        return Nodes(self.children.get(selector, []))

    async def inner_text(self, **kwargs):
        return self.text

    async def get_attribute(self, name):
        return self.attrs.get(name)

    async def screenshot(self, path, **kwargs):
        Path(path).write_bytes(b"fixture-scoped-screenshot")

    async def click(self, **kwargs):
        pass


class Page(Node):
    def __init__(self, url="https://x.com/search", body="Search results", children=None, navigation_error=None):
        super().__init__(children={"body": [Node(body)], **(children or {})})
        self.url = url
        self.navigation_error = navigation_error
        self.closed = False

    async def goto(self, url, **kwargs):
        if self.navigation_error:
            raise self.navigation_error
        self.url = url

    async def wait_for_timeout(self, milliseconds):
        pass

    async def wait_for_selector(self, selector, **kwargs):
        pass

    async def route(self, pattern, handler):
        self.handler = handler

    async def evaluate(self, script):
        return 100

    async def close(self):
        self.closed = True


def tweet(identity="123", text="Parimatch withdrawal still pending. Exact punctuation: ₹500!"):
    return Node(children={
        'a[href*="/status/"]:has(time)': [Node(attrs={"href": f"/alice/status/{identity}"})],
        'a[href*="/status/"]': [Node(attrs={"href": f"/alice/status/{identity}"})],
        '[data-testid="tweetText"]': [Node(text)],
        '[data-testid="User-Name"]': [Node("Alice\n@alice")],
        "time[datetime]": [Node(attrs={"datetime": "2026-09-09T05:00:00Z"})],
    }, text=text)


def finding(identity="123"):
    return Observation("x_authenticated_playwright", "Social", "AUTOMATED_SOCIAL_FINDING",
        "Parimatch complaint", f"https://x.com/alice/status/{identity}", confidence=0.65,
        metadata={"post_text": "Parimatch withdrawal…", "search_url": "https://x.com/search?q=Parimatch",
                  "screenshot_paths": ["search.png"], "screenshot_sha256": "search-hash"})


class SocialCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_requested_post_excludes_replies_and_sidebar(self):
        requested = tweet()
        page = Page(url="https://x.com/alice/status/123", children={
            'article[data-testid="tweet"], article': [tweet("456", "Unrelated reply"), requested],
        }, body="Search and sidebar contain unrelated promotions")
        metadata, root = await extract_post(page, "x", page.url)
        self.assertIs(root, requested)
        self.assertEqual(metadata["post_text"], "Parimatch withdrawal still pending. Exact punctuation: ₹500!")
        self.assertEqual(metadata["author"], "Alice\n@alice")
        self.assertEqual(metadata["published_at"], "2026-09-09T05:00:00Z")
        self.assertNotIn("promotions", metadata["post_text"])

    async def test_permalink_redirect_to_different_post_is_not_accepted(self):
        page = Page(url="https://x.com/alice/status/456", children={'article[data-testid="tweet"], article': [tweet("456")]})
        with self.assertRaisesRegex(ValueError, "PERMALINK_MISMATCH"):
            await extract_post(page, "x", "https://x.com/alice/status/123")

    async def test_success_retains_snippet_and_labels_each_screenshot_source(self):
        page = Page(children={'article[data-testid="tweet"], article': [tweet()]})
        browser = SimpleNamespace(new_page=AsyncMock(return_value=page))
        observation = finding()
        with tempfile.TemporaryDirectory() as directory:
            counts = await enrich_social_findings(browser, "x", [observation], CollectorContext([]), Path(directory))
        self.assertEqual(counts["detailed_captures"], 1)
        self.assertEqual(observation.metadata["search_snippet"], "Parimatch withdrawal…")
        self.assertEqual(observation.metadata["content_scope"], "post_text")
        self.assertEqual(observation.metadata["screenshot_scope"], "search_results_and_post")
        self.assertEqual([p["scope"] for p in observation.metadata["screenshot_provenance"]], ["search_results", "post_container"])
        self.assertEqual(observation.metadata["screenshot_provenance"][1]["url"], observation.source_url)
        self.assertTrue(page.closed)

    async def test_inaccessible_post_keeps_snippet_and_limit_does_not_drop_findings(self):
        page = Page(navigation_error=TimeoutError("private error URL must not be exposed"))
        browser = SimpleNamespace(new_page=AsyncMock(return_value=page))
        observations = [finding("123"), finding("456")]
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"SOCIAL_POST_CAPTURE_LIMIT": "1"}):
            counts = await enrich_social_findings(browser, "x", observations, CollectorContext([]), Path(directory))
        self.assertEqual(counts["unavailable"], 1)
        self.assertEqual(counts["budget_skipped"], 1)
        self.assertEqual(browser.new_page.await_count, 1)
        self.assertEqual(observations[0].metadata["post_text"], "Parimatch withdrawal…")
        self.assertEqual(observations[0].metadata["content_scope"], "search_snippet")
        self.assertEqual(observations[1].metadata["capture_status"], "budget_skipped")
        self.assertNotIn("private error", observations[0].metadata["capture_reason"])
        self.assertLess(observations[0].confidence, 0.9)

    async def test_youtube_captures_description_not_recommendations_or_video_claims(self):
        root = Node(children={"h1": [Node("Parimatch review")],
            "#description-inline-expander, #description": [Node("Exact creator description")],
            "ytd-channel-name": [Node("Review channel")]})
        page = Page(url="https://www.youtube.com/watch?v=abc", body="Unrelated recommended video",
                    children={"ytd-watch-metadata": [root]})
        metadata, _ = await extract_post(page, "youtube", page.url)
        self.assertEqual(metadata["post_text"], "Parimatch review\nExact creator description")
        self.assertEqual(metadata["content_scope"], "video_description")
        self.assertIsNone(metadata["published_at"])

    async def test_empty_results_must_be_explicit_and_login_is_failed(self):
        with self.assertRaisesRegex(RuntimeError, "SEARCH_LAYOUT_UNRECOGNIZED"):
            await validate_social_page(Page(body="Loading a redesigned search interface"), "x", 0)
        diagnostics = await validate_social_page(Page(body='No results for "Parimatch"'), "x", 0)
        self.assertEqual(diagnostics["search_status"], "no_results")
        self.assertEqual(diagnostics["authentication"], "unverified")
        with self.assertRaisesRegex(RuntimeError, "SESSION_EXPIRED"):
            await validate_social_page(Page(url="https://x.com/i/flow/login"), "x", 0)
        with self.assertRaisesRegex(RuntimeError, "ACCESS_CHALLENGED"):
            await validate_social_page(Page(body="Verify you are human"), "x", 0)

    async def test_cancel_stops_before_another_permalink_visit(self):
        browser = SimpleNamespace(new_page=AsyncMock())
        with self.assertRaises(InvestigationCancelled):
            await enrich_social_findings(browser, "x", [finding()], CollectorContext([], cancel_check=lambda: True), Path("/tmp"))
        browser.new_page.assert_not_called()

    async def test_navigation_guard_blocks_private_resources_and_external_redirects(self):
        page = Page()
        await install_navigation_guard(page, "x")
        for url, navigation, addresses in [
            ("https://127.0.0.1/admin", True, ["127.0.0.1"]),
            ("https://internal.example/image", False, []),
            ("https://x.com.evil.example/post", True, ["8.8.8.8"]),
        ]:
            route = SimpleNamespace(request=SimpleNamespace(url=url, is_navigation_request=lambda: navigation),
                                    abort=AsyncMock(), continue_=AsyncMock())
            with patch("osint.collectors.social_capture.DomainNormalizer.public_addresses", return_value=addresses):
                await page.handler(route)
            route.abort.assert_awaited_once()
            route.continue_.assert_not_called()

    async def test_x_max_posts_path_still_enriches_and_records_diagnostics(self):
        search = Page(children={"article": [tweet()], AUTH_SELECTORS["x"]: [Node()]})
        detail = Page(children={'article[data-testid="tweet"], article': [tweet()]})
        resources = SimpleNamespace(context=SimpleNamespace(new_page=AsyncMock(side_effect=[search, detail])))
        with tempfile.TemporaryDirectory() as directory, \
                patch("osint.collectors.x_authenticated.EVIDENCE_DIR", Path(directory)), \
                patch("osint.collectors.x_authenticated.launch_browser_session", AsyncMock(return_value=resources)), \
                patch("osint.collectors.x_authenticated.close_browser_session", AsyncMock()), \
                patch("osint.collectors.x_authenticated.wait_for_viewport_readiness", AsyncMock()), \
                patch.dict(os.environ, {"X_MAX_POSTS": "1"}):
            observations = await XAuthenticatedCollector()._collect(
                NormalizedTarget("parimatch.com", "parimatch.com", "https://parimatch.com", "Parimatch"), CollectorContext([]))
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0].metadata["capture_status"], "captured")
        self.assertEqual(observations[1].entity_type, "SOCIAL_COLLECTION_DIAGNOSTIC")
        self.assertEqual(observations[1].metadata["authentication"], "verified")
        self.assertEqual(observations[1].metadata["detailed_captures"], 1)


class SocialUrlTests(unittest.TestCase):
    def test_profiles_and_untrusted_urls_are_not_posts(self):
        for url in ("https://x.com/alice", "http://x.com/alice/status/1", "https://x.com:8443/alice/status/1", "https://evil.example/alice/status/1"):
            self.assertEqual(post_identity(url, "x"), "")
        self.assertFalse(platform_url_allowed("https://x.com@evil.example/alice/status/1", "x"))
        self.assertEqual(post_identity("https://www.youtube.com/@creator", "youtube"), "")
        self.assertEqual(post_identity("https://t.me/channel/123", "telegram"), "channel/123")
        self.assertEqual(post_identity("https://www.instagram.com/p/ABC12/", "instagram"), "ABC12")


if __name__ == "__main__":
    unittest.main()
