from __future__ import annotations

import shutil
import subprocess
import tempfile
import hashlib
import re
from xml.etree import ElementTree
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw

from osint.models import NormalizedTarget
from osint.relevance import build_target_variants, find_target_reference, target_keyword_proximity
from osint.text_cleanup import clean_evidence_text


@dataclass(frozen=True)
class DocumentAssessment:
    accepted: bool
    document_type: str = "Other Target-Related Document"
    matched_target_variant: str = ""
    matched_keywords: tuple[str, ...] = ()
    relevant_pages: tuple[int, ...] = ()
    evidence_context: str = ""
    reason: str = ""
    page_count: int = 0


DOCUMENT_CATEGORIES = (
    ("Registration / Company", ("company registration", "certificate of incorporation", "registered office", "company number")),
    ("Licence / Certificate", ("licence", "license", "licensed by", "certificate", "certification")),
    ("Legal / Regulatory", ("court order", "legal notice", "blocking order", "regulator", "regulatory")),
    ("Terms / Policies", ("terms and conditions", "privacy policy", "withdrawal policy", "deposit policy")),
    ("Payment / Deposit / Withdrawal", ("deposit", "withdrawal", "wallet", "payment", "upi", "payout")),
    ("Application / APK", ("apk", "android app", "mobile application", "ios", "ipa")),
    ("Bonus / Promotion", ("welcome bonus", "deposit bonus", "cashback", "free bet", "promotion")),
    ("Review / Analysis", ("review", "complaint", "analysis", "scam", "fraud")),
)


def extract_pdf_pages(content: bytes, timeout: int = 20) -> list[str]:
    """Extract page-delimited text with the local Poppler utility and bounded runtime."""
    executable = shutil.which("pdftotext")
    if not executable:
        return []
    with tempfile.TemporaryDirectory(prefix="osint_pdf_") as temp_dir:
        source = Path(temp_dir) / "source.pdf"
        source.write_bytes(content)
        completed = subprocess.run(
            [executable, "-layout", str(source), "-"],
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    if completed.returncode != 0:
        return []
    pages = completed.stdout.decode("utf-8", errors="replace").split("\f")
    # pdftotext terminates its output with a form-feed.  That delimiter is not
    # an additional PDF page and previously inflated the page count by one.
    if pages and not pages[-1].strip():
        pages.pop()
    return pages


def assess_pdf(content: bytes, target: NormalizedTarget, evidence_keywords: list[str] | tuple[str, ...]) -> DocumentAssessment:
    pages = extract_pdf_pages(content)
    if not pages:
        return DocumentAssessment(False, reason="PDF text could not be extracted; manual review required")
    return assess_document_pages(pages, target, evidence_keywords)


def extract_docx_text(content: bytes) -> list[str]:
    """Extract paragraphs and table cells from a bounded DOCX payload."""
    try:
        from docx import Document

        document = Document(BytesIO(content))
    except Exception:
        return []
    blocks = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
    for table in document.tables:
        for row in table.rows:
            blocks.extend(cell.text for cell in row.cells if cell.text.strip())
    return ["\n".join(blocks)] if blocks else []


def assess_docx(
    content: bytes,
    target: NormalizedTarget,
    evidence_keywords: list[str] | tuple[str, ...],
) -> DocumentAssessment:
    pages = extract_docx_text(content)
    if not pages:
        return DocumentAssessment(False, reason="DOCX text could not be extracted; manual review required")
    return assess_document_pages(pages, target, evidence_keywords)


def assess_document_pages(
    pages: list[str],
    target: NormalizedTarget,
    evidence_keywords: list[str] | tuple[str, ...],
) -> DocumentAssessment:
    """Apply the same target and evidence checks to any extracted document text."""
    variants = build_target_variants(target)
    target_hits = [(number, find_target_reference(text, variants)) for number, text in enumerate(pages, 1)]
    target_hits = [(number, variant) for number, variant in target_hits if variant]
    if not target_hits:
        return DocumentAssessment(False, reason="No verified target reference found in extracted PDF text")

    keywords = tuple(dict.fromkeys(keyword for keyword in evidence_keywords if keyword))
    matches: list[tuple[int, str, str, int]] = []
    contexts = []
    for number, text in enumerate(pages, 1):
        normalized = " ".join(text.split())
        proximity = target_keyword_proximity(normalized, variants, keywords)
        if not proximity:
            continue
        target_variant, keyword, distance = proximity
        lowered = normalized.casefold()
        keyword_index = lowered.find(keyword.casefold())
        start = max(keyword_index - 180, 0)
        end = min(keyword_index + len(keyword) + 300, len(normalized))
        contexts.append(f"Page {number}: {normalized[start:end]}")
        matches.append((number, target_variant, keyword, distance))

    full_text = "\n".join(pages).casefold()
    document_type = next(
        (category for category, terms in DOCUMENT_CATEGORIES if any(term in full_text for term in terms)),
        "Other Target-Related Document",
    )
    if not matches:
        return DocumentAssessment(
            False,
            document_type=document_type,
            reason="Target reference found, but no configured evidence term occurred within the proximity limit",
            page_count=len(pages),
        )
    return DocumentAssessment(
        True,
        document_type=document_type,
        matched_target_variant=(matches[0][1] if matches else target_hits[0][1]),
        matched_keywords=tuple(sorted({item[2] for item in matches}, key=str.casefold)),
        relevant_pages=tuple(sorted({item[0] for item in matches} or {target_hits[0][0]})),
        evidence_context=clean_evidence_text("\n\n".join(contexts), limit=12_000),
        reason="Verified target reference and target-specific document evidence",
        page_count=len(pages),
    )


def _pdf_word_boxes(
    pdf_path: str | Path,
    requested_pages: set[int],
    timeout: int,
) -> dict[int, dict]:
    """Extract positioned PDF words for deterministic screenshot highlighting."""
    executable = shutil.which("pdftotext")
    if not executable:
        return {}
    completed = subprocess.run(
        [executable, "-bbox-layout", str(pdf_path), "-"],
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        return {}
    try:
        root = ElementTree.fromstring(completed.stdout)
    except ElementTree.ParseError:
        return {}
    pages: dict[int, dict] = {}
    for page_number, page in enumerate(root.findall(".//{*}page"), 1):
        if page_number not in requested_pages:
            continue
        words = []
        for word in page.findall(".//{*}word"):
            text = "".join(word.itertext()).strip()
            try:
                box = tuple(float(word.attrib[name]) for name in ("xMin", "yMin", "xMax", "yMax"))
            except (KeyError, ValueError):
                continue
            if text:
                words.append((text, box))
        pages[page_number] = {
            "width": float(page.attrib.get("width", 1)),
            "height": float(page.attrib.get("height", 1)),
            "words": words,
        }
    return pages


def _highlight_pdf_terms(image_path: Path, page_data: dict, terms: tuple[str, ...]) -> int:
    """Highlight exact single- or multi-word target variants on a rendered PDF page."""
    normalized_terms = {
        re.sub(r"[^a-z0-9]+", "", term.casefold())
        for term in terms
        if re.sub(r"[^a-z0-9]+", "", term.casefold())
    }
    if not normalized_terms or not page_data.get("words"):
        return 0
    words = page_data["words"]
    matches: list[tuple[float, float, float, float]] = []
    for start in range(len(words)):
        combined = ""
        boxes = []
        for index in range(start, min(start + 6, len(words))):
            combined += re.sub(r"[^a-z0-9]+", "", words[index][0].casefold())
            boxes.append(words[index][1])
            if combined in normalized_terms:
                matches.append((
                    min(box[0] for box in boxes),
                    min(box[1] for box in boxes),
                    max(box[2] for box in boxes),
                    max(box[3] for box in boxes),
                ))
            if not any(term.startswith(combined) for term in normalized_terms):
                break
    if not matches:
        return 0
    with Image.open(image_path) as source:
        image = source.convert("RGBA")
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    scale_x = image.width / max(float(page_data.get("width", 1)), 1)
    scale_y = image.height / max(float(page_data.get("height", 1)), 1)
    for x_min, y_min, x_max, y_max in matches:
        box = (
            max(0, int(x_min * scale_x) - 4),
            max(0, int(y_min * scale_y) - 3),
            min(image.width, int(x_max * scale_x) + 4),
            min(image.height, int(y_max * scale_y) + 3),
        )
        draw.rectangle(box, fill=(255, 235, 59, 90), outline=(255, 59, 48, 255), width=4)
    Image.alpha_composite(image, overlay).convert("RGB").save(image_path, "PNG")
    return len(matches)


def render_pdf_pages(
    pdf_path: str | Path,
    page_numbers: tuple[int, ...],
    output_dir: str | Path,
    highlight_terms: tuple[str, ...] = (),
) -> list[dict]:
    """Render requested PDF pages and highlight verified target references."""
    executable = shutil.which("pdftoppm")
    if not executable:
        return []
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    requested = tuple(sorted({number for number in page_numbers if number > 0}))
    if not requested:
        return []
    captures = []
    requested_set = set(requested)
    word_boxes = _pdf_word_boxes(
        pdf_path,
        requested_set,
        timeout=max(30, len(requested) * 10),
    ) if highlight_terms else {}
    # Render one page per process.  A single pdftoppm invocation can hold every
    # rendered page in memory and be killed for otherwise valid large PDFs.
    for page_number in requested:
        prefix = destination / f"page-{page_number}"
        completed = subprocess.run(
            [
                executable, "-f", str(page_number), "-l", str(page_number),
                "-singlefile", "-png", "-r", "144", str(pdf_path), str(prefix),
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        image_path = prefix.with_suffix(".png")
        if completed.returncode != 0 or not image_path.is_file():
            continue
        highlight_count = _highlight_pdf_terms(
            image_path,
            word_boxes.get(page_number, {}),
            highlight_terms,
        )
        content = image_path.read_bytes()
        captures.append({
            "page": page_number,
            "path": str(image_path),
            "sha256": hashlib.sha256(content).hexdigest(),
            "highlighted_target_matches": highlight_count,
        })
    return captures


def render_docx_pages(
    docx_path: str | Path,
    output_dir: str | Path,
    target: NormalizedTarget,
    evidence_keywords: list[str] | tuple[str, ...],
) -> list[dict]:
    """Render only context-validated DOCX pages through a temporary PDF conversion."""
    office = shutil.which("libreoffice") or shutil.which("soffice")
    if not office:
        return []
    source = Path(docx_path)
    if not source.is_file():
        return []
    with tempfile.TemporaryDirectory(prefix="osint_docx_render_") as temp_dir:
        converted_dir = Path(temp_dir) / "converted"
        converted_dir.mkdir()
        try:
            completed = subprocess.run(
                [office, "--headless", "--convert-to", "pdf", "--outdir", str(converted_dir), str(source)],
                capture_output=True, check=False, timeout=60, cwd=temp_dir,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        pdf_path = converted_dir / f"{source.stem}.pdf"
        if completed.returncode != 0 or not pdf_path.is_file():
            return []
        assessment = assess_pdf(pdf_path.read_bytes(), target, evidence_keywords)
        if not assessment.accepted:
            return []
        return render_pdf_pages(
            pdf_path, assessment.relevant_pages, output_dir,
            highlight_terms=tuple(dict.fromkeys((assessment.matched_target_variant, *assessment.matched_keywords))),
        )
