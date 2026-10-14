"""Readiness checks for sequential screenshots of dynamic feeds."""


async def wait_for_viewport_readiness(page, content_selector: str, *, timeout: int = 10_000) -> None:
    """Require visible content and a settled viewport; propagate readiness timeouts.

    Only visible images and loaders matter: feeds may retain offscreen loaders.
    The stability interval is conditional polling, not an unconditional sleep.
    """
    await page.wait_for_load_state("domcontentloaded", timeout=timeout)
    handle = await page.wait_for_function(
        """selector => {
            const visible = el => {
                const r = el.getBoundingClientRect();
                const s = getComputedStyle(el);
                return r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0
                    && r.top < innerHeight && r.left < innerWidth
                    && s.visibility !== 'hidden' && s.display !== 'none' && s.opacity !== '0';
            };
            const content = [...document.querySelectorAll(selector)].filter(visible);
            const loading = [...document.querySelectorAll(
                '[role="progressbar"], [aria-busy="true"], .loading-overlay, .loading-spinner'
            )].some(visible);
            const imagesReady = [...document.images].filter(visible).every(img => img.complete);
            const ready = content.length > 0 && !loading && imagesReady
                && (!document.fonts || document.fonts.status === 'loaded');
            const signature = JSON.stringify(content.map(el => {
                const r = el.getBoundingClientRect();
                return [el.textContent, r.x, r.y, r.width, r.height];
            }));
            const state = window.__osintViewportReadiness;
            if (!ready || !state || state.signature !== signature) {
                window.__osintViewportReadiness = {signature, since: performance.now()};
                return false;
            }
            return performance.now() - state.since >= 500;
        }""",
        arg=content_selector,
        polling=100,
        timeout=timeout,
    )
    await handle.dispose()
