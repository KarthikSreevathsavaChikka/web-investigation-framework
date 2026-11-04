"""Optional artwork for the two header positions in the shared report design."""

from __future__ import annotations

from pathlib import Path


ASSET_DIR = Path(__file__).resolve().parent.parent / "ui" / "assets"
LEFT_LOGO = ASSET_DIR / "report_header_left.png"
RIGHT_LOGO = ASSET_DIR / "report_header_right.png"
