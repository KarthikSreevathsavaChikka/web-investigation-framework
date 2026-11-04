"""VirusTotal intelligence integration."""

from virustotal.client import VirusTotalClient, VirusTotalError, normalize_vt_report
from virustotal.storage import VirusTotalRepository

__all__ = ["VirusTotalClient", "VirusTotalError", "VirusTotalRepository", "normalize_vt_report"]
