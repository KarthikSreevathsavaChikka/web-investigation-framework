import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Set, Tuple
from config import HIGH_PRIORITY_KEYWORDS, MEDIUM_PRIORITY_KEYWORDS, LOW_PRIORITY_KEYWORDS

class NavigationEngine:
    """Step 4 & 5: Builds navigation map and prioritizes links into High, Medium, and Low buckets."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.parsed_base = urllib.parse.urlparse(base_url)
        self.base_domain = self.parsed_base.netloc.lower()

    def get_link_priority(self, url: str, anchor_text: str = "") -> str:
        """Determines link priority: 'High', 'Medium', or 'Low' based on URL path & anchor text."""
        combined = f"{url} {anchor_text}".lower()

        # Check High Priority
        for kw in HIGH_PRIORITY_KEYWORDS:
            if kw in combined:
                return "High"

        # Check Medium Priority
        for kw in MEDIUM_PRIORITY_KEYWORDS:
            if kw in combined:
                return "Medium"

        # Check Low Priority
        for kw in LOW_PRIORITY_KEYWORDS:
            if kw in combined:
                return "Low"

        # Default to Medium for uncategorized internal links
        return "Medium"

    def is_internal_link(self, url: str) -> bool:
        """Verifies if a link belongs to the target domain and is valid HTTP/HTTPS."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ["http", "https"]:
                return False
            # Match domain or subdomain
            domain = parsed.netloc.lower()
            return self.base_domain in domain or domain in self.base_domain
        except Exception:
            return False

    def normalize_url(self, href: str, current_url: str) -> str:
        """Resolves relative links, strips hash fragments, and removes tracking query parameters."""
        full_url = urllib.parse.urljoin(current_url, href)
        parsed = urllib.parse.urlparse(full_url)
        
        # Filter out tracking and redundant query parameters (e.g. source_type, ref, utm_*, lang)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        filtered_params = {
            k: v for k, v in query_params.items() 
            if k.lower() not in ["source_type", "ref", "utm_source", "utm_medium", "utm_campaign", "lang", "language", "session", "click_id"]
        }
        clean_query = urllib.parse.urlencode(filtered_params, doseq=True)

        # Rebuild without fragment (#) or trailing duplicate slashes
        clean_url = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path.rstrip('/') if parsed.path != '/' else '/',
            parsed.params,
            clean_query,
            '' # drop fragment
        ))
        return clean_url

    def extract_and_prioritize_links(self, html_content: str, current_url: str) -> List[Dict[str, str]]:
        """
        Extracts all internal links from HTML (nav menus, headers, footers, buttons, cards),
        prioritizes them, and returns a sorted list (High Priority first).
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        discovered: Dict[str, Dict[str, str]] = {}

        # 1. Extract standard <a> tags
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            anchor_text = a.get_text(strip=True)
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                continue
            
            normalized = self.normalize_url(href, current_url)
            if self.is_internal_link(normalized):
                priority = self.get_link_priority(normalized, anchor_text)
                if normalized not in discovered or priority == "High":
                    discovered[normalized] = {
                        "url": normalized,
                        "anchor_text": anchor_text,
                        "priority": priority
                    }

        # 2. Extract buttons or cards with data-href or onclick attributes
        for el in soup.find_all(['button', 'div', 'li'], attrs={'data-href': True}):
            href = el['data-href'].strip()
            normalized = self.normalize_url(href, current_url)
            if self.is_internal_link(normalized):
                priority = self.get_link_priority(normalized, el.get_text(strip=True))
                discovered[normalized] = {
                    "url": normalized,
                    "anchor_text": el.get_text(strip=True),
                    "priority": priority
                }

        # Priority Sort Order: High -> Medium -> Low
        priority_rank = {"High": 1, "Medium": 2, "Low": 3}
        sorted_links = sorted(discovered.values(), key=lambda x: priority_rank.get(x["priority"], 2))

        return sorted_links
