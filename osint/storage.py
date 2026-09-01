from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from database.connection import connect_database, is_postgresql_connection
from database.migrations import lock_schema_migration, record_schema_version, schema_version_exists
from osint.models import (
    CollectorResult,
    DorkQuery,
    NormalizedTarget,
    Observation,
    PageCaptureRecord,
    TargetResolution,
)
from osint.risk import RiskAssessment
from osint.resolver import TargetResolver


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class OSINTRepository:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = str(db_path) if db_path is not None else None
        self.init_schema()

    def connection(self):
        return connect_database(self.db_path)

    def init_schema(self) -> None:
        with self.connection() as connection:
            lock_schema_migration(connection)
            if is_postgresql_connection(connection) and schema_version_exists(connection, "osint", 2):
                return
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS osint_investigations (
                    id TEXT PRIMARY KEY,
                    target_domain TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'Informational',
                    risk_confidence REAL DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS osint_collector_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_seconds REAL DEFAULT 0.0,
                    observation_count INTEGER DEFAULT 0,
                    error TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    query TEXT NOT NULL,
                    description TEXT,
                    provider TEXT NOT NULL,
                    UNIQUE(investigation_id, query),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    category TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    risk_points INTEGER DEFAULT 0,
                    metadata_json TEXT NOT NULL,
                    evidence_hash TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    UNIQUE(investigation_id, evidence_hash),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_risk_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    value TEXT NOT NULL,
                    points INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    source_url TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_target_candidates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reason TEXT NOT NULL,
                    appearances INTEGER DEFAULT 1,
                    selected INTEGER DEFAULT 0,
                    UNIQUE(investigation_id, domain),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_domain_traffic_cache (
                    domain TEXT PRIMARY KEY,
                    monthly_visits INTEGER,
                    yearly_visits INTEGER,
                    yearly_visits_kind TEXT,
                    traffic_source TEXT NOT NULL,
                    traffic_data_date TEXT,
                    error TEXT,
                    refreshed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS osint_search_identities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    identity_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reason TEXT NOT NULL,
                    UNIQUE(investigation_id, value),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    title TEXT,
                    snippet TEXT,
                    source_type TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    UNIQUE(investigation_id, normalized_url),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_source_query_map (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    query_id TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    search_engine TEXT NOT NULL,
                    search_rank INTEGER NOT NULL,
                    UNIQUE(source_id, query_id, search_engine),
                    FOREIGN KEY (source_id) REFERENCES osint_sources(id)
                );

                CREATE TABLE IF NOT EXISTS osint_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    final_url TEXT,
                    document_type TEXT,
                    local_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    discovered_at TEXT NOT NULL,
                    UNIQUE(investigation_id, sha256),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_analyst_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_search_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    query_id TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    search_rank INTEGER NOT NULL,
                    title TEXT,
                    source_url TEXT NOT NULL,
                    snippet TEXT,
                    normalized_url TEXT,
                    source_type TEXT,
                    relevance_status TEXT NOT NULL,
                    matched_target_variant TEXT,
                    relevance_field TEXT,
                    relevance_reason TEXT,
                    provider_semantic_quality TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    UNIQUE(investigation_id, query_id, provider, search_rank, source_url),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_query_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    query_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    raw_results INTEGER NOT NULL,
                    accepted_results INTEGER NOT NULL,
                    rejected_irrelevant INTEGER NOT NULL,
                    provider_semantic_quality TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    UNIQUE(investigation_id, query_id, provider),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );

                CREATE TABLE IF NOT EXISTS osint_page_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    source_url TEXT NOT NULL,
                    final_url TEXT,
                    page_title TEXT,
                    http_status INTEGER,
                    accessibility_status TEXT NOT NULL,
                    failure_reason TEXT,
                    captured_at TEXT NOT NULL,
                    UNIQUE(investigation_id, source_id),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id),
                    FOREIGN KEY (source_id) REFERENCES osint_sources(id)
                );

                CREATE TABLE IF NOT EXISTS osint_evidence_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_capture_id INTEGER NOT NULL,
                    query_id TEXT NOT NULL,
                    query_name TEXT,
                    query_category TEXT,
                    search_engine TEXT,
                    serp_rank INTEGER,
                    matched_keywords_json TEXT NOT NULL,
                    matched_phrases_json TEXT NOT NULL,
                    evidence_text TEXT,
                    context_text TEXT,
                    match_method TEXT,
                    confidence REAL NOT NULL,
                    FOREIGN KEY (page_capture_id) REFERENCES osint_page_captures(id)
                );

                CREATE TABLE IF NOT EXISTS osint_evidence_screenshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_match_id INTEGER NOT NULL,
                    screenshot_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    UNIQUE(evidence_match_id, sha256),
                    FOREIGN KEY (evidence_match_id) REFERENCES osint_evidence_matches(id)
                );

                CREATE TABLE IF NOT EXISTS osint_document_page_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    source_id INTEGER NOT NULL,
                    query_id TEXT NOT NULL,
                    query_name TEXT,
                    search_engine TEXT,
                    source_url TEXT NOT NULL,
                    final_url TEXT,
                    page_number INTEGER NOT NULL,
                    screenshot_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    UNIQUE(investigation_id, source_id, query_id, page_number, sha256),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id),
                    FOREIGN KEY (source_id) REFERENCES osint_sources(id)
                );

                CREATE TABLE IF NOT EXISTS osint_social_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    post_url TEXT NOT NULL,
                    normalized_post_url TEXT NOT NULL,
                    title TEXT,
                    post_text TEXT,
                    matched_target TEXT,
                    confidence REAL NOT NULL,
                    collector_method TEXT NOT NULL,
                    query_id TEXT,
                    search_engine TEXT,
                    search_rank INTEGER,
                    status TEXT NOT NULL,
                    screenshot_paths_json TEXT DEFAULT '[]',
                    collected_at TEXT NOT NULL,
                    UNIQUE(investigation_id, normalized_post_url),
                    FOREIGN KEY (investigation_id) REFERENCES osint_investigations(id)
                );
                """
            )

            self._ensure_column(connection, "osint_investigations", "original_input", "TEXT")
            self._ensure_column(connection, "osint_investigations", "normalized_input", "TEXT")
            self._ensure_column(connection, "osint_investigations", "input_type", "TEXT")
            self._ensure_column(connection, "osint_investigations", "resolved_brand", "TEXT")
            self._ensure_column(connection, "osint_investigations", "resolution_confidence", "REAL DEFAULT 0.0")
            self._ensure_column(connection, "osint_investigations", "resolution_reason", "TEXT")
            self._ensure_column(connection, "osint_queries", "query_id", "TEXT")
            self._ensure_column(connection, "osint_queries", "name", "TEXT")
            self._ensure_column(connection, "osint_queries", "priority", "TEXT DEFAULT 'medium'")
            self._ensure_column(connection, "osint_queries", "enabled", "INTEGER DEFAULT 1")
            self._ensure_column(connection, "osint_queries", "evidence_keywords_json", "TEXT DEFAULT '[]'")
            self._ensure_column(connection, "osint_queries", "target_requirement", "TEXT DEFAULT 'required'")
            self._ensure_column(connection, "osint_queries", "document_type", "TEXT DEFAULT ''")
            self._ensure_column(connection, "osint_sources", "relevance_status", "TEXT DEFAULT 'legacy_unreviewed'")
            self._ensure_column(connection, "osint_sources", "matched_target_variant", "TEXT")
            self._ensure_column(connection, "osint_sources", "relevance_field", "TEXT")
            self._ensure_column(connection, "osint_sources", "relevance_reason", "TEXT")
            self._ensure_column(connection, "osint_page_captures", "matched_target_variant", "TEXT")
            self._ensure_column(connection, "osint_page_captures", "relevance_field", "TEXT")
            self._ensure_column(connection, "osint_evidence_matches", "matched_target_variant", "TEXT")
            self._ensure_column(connection, "osint_evidence_matches", "target_keyword_distance", "INTEGER")
            self._ensure_column(connection, "osint_documents", "matched_target_variant", "TEXT")
            self._ensure_column(connection, "osint_documents", "matched_keywords_json", "TEXT DEFAULT '[]'")
            self._ensure_column(connection, "osint_documents", "relevant_pages_json", "TEXT DEFAULT '[]'")
            self._ensure_column(connection, "osint_documents", "evidence_context", "TEXT")
            self._ensure_column(connection, "osint_documents", "relevance_status", "TEXT DEFAULT 'confirmed_evidence'")
            self._ensure_column(connection, "osint_documents", "page_screenshots_json", "TEXT DEFAULT '[]'")
            self._ensure_column(connection, "osint_documents", "file_name", "TEXT")
            self._ensure_column(connection, "osint_documents", "media_type", "TEXT")
            self._ensure_column(connection, "osint_documents", "content_blob", "BYTEA")
            self._ensure_column(connection, "osint_documents", "discovery_queries_json", "TEXT DEFAULT '[]'")
            self._ensure_column(connection, "osint_query_executions", "status", "TEXT DEFAULT 'completed'")
            self._ensure_column(connection, "osint_social_findings", "screenshot_paths_json", "TEXT DEFAULT '[]'")
            for column, definition in (
                ("domain_status", "TEXT DEFAULT 'Unknown'"), ("detailed_status", "TEXT DEFAULT 'Unknown'"),
                ("http_status", "TEXT DEFAULT 'Unavailable'"), ("final_url", "TEXT"),
                ("response_time_ms", "INTEGER"), ("check_error", "TEXT"), ("checked_at", "TEXT"),
                ("monthly_visits", "INTEGER"), ("yearly_visits", "INTEGER"),
                ("yearly_visits_kind", "TEXT DEFAULT 'Unavailable'"), ("traffic_source", "TEXT DEFAULT 'Unavailable'"),
                ("traffic_data_date", "TEXT"),
            ):
                self._ensure_column(connection, "osint_target_candidates", column, definition)
            record_schema_version(connection, "osint", 2)

    @staticmethod
    def _ensure_column(connection, table: str, column: str, definition: str) -> None:
        if is_postgresql_connection(connection):
            connection.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}")
            return
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def create_investigation(
        self,
        investigation_id: str,
        target: NormalizedTarget,
        resolution: TargetResolution | None = None,
    ) -> None:
        selected = (
            next((candidate for candidate in resolution.candidates if candidate.domain == target.domain), None)
            if resolution
            else None
        )
        with self.connection() as connection:
            connection.execute(
                """
                INSERT INTO osint_investigations
                (id, target_domain, target_url, started_at, status, original_input,
                 normalized_input, input_type, resolved_brand, resolution_confidence, resolution_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    target.domain,
                    target.url,
                    utc_now(),
                    "RUNNING",
                    resolution.original_input if resolution else target.raw_input,
                    resolution.normalized_input if resolution else target.domain,
                    resolution.input_type if resolution else "domain",
                    resolution.resolved_brand if resolution else target.brand,
                    selected.confidence if selected else 1.0,
                    selected.reason if selected else "Valid domain supplied directly",
                ),
            )
            if resolution:
                connection.executemany(
                    """
                    INSERT OR REPLACE INTO osint_target_candidates
                    (investigation_id, domain, confidence, reason, appearances, selected)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            investigation_id,
                            candidate.domain,
                            candidate.confidence,
                            candidate.reason,
                            candidate.appearances,
                            1 if candidate.domain == target.domain else 0,
                        )
                        for candidate in resolution.candidates
                    ],
                )
            connection.executemany(
                """
                INSERT OR IGNORE INTO osint_search_identities
                (investigation_id, value, identity_type, confidence, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (investigation_id, item.value, item.identity_type, item.confidence, item.reason)
                    for item in TargetResolver.build_search_identities(target)
                ],
            )

    def save_queries(self, investigation_id: str, queries: Iterable[DorkQuery]) -> None:
        with self.connection() as connection:
            connection.executemany(
                """
                INSERT OR IGNORE INTO osint_queries
                (investigation_id, query_id, category, name, priority, query, description,
                 provider, enabled, evidence_keywords_json, target_requirement, document_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        investigation_id, item.query_id, item.category, item.name, item.priority,
                        item.query, item.description, item.provider, 1 if item.enabled else 0,
                        json.dumps(item.evidence_keywords),
                        item.target_requirement, item.document_type,
                    )
                    for item in queries
                ],
            )

    def save_collector_result(self, investigation_id: str, result: CollectorResult) -> None:
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO osint_collector_runs (investigation_id, collector, status, duration_seconds, observation_count, error) VALUES (?, ?, ?, ?, ?, ?)",
                (investigation_id, result.collector, result.status, result.duration_seconds, len(result.observations), result.error),
            )
            for observation in result.observations:
                if observation.entity_type == "QUERY_EXECUTION":
                    self._save_query_execution(connection, investigation_id, observation)
                    continue
                if observation.entity_type in {"SEARCH_RESULT", "SEARCH_RESULT_REJECTED"}:
                    self._save_search_result_audit(connection, investigation_id, observation)
                if observation.entity_type in {"SEARCH_RESULT_REJECTED", "PAGE_REJECTED_IRRELEVANT"}:
                    continue
                digest_source = "\0".join(
                    (observation.collector, observation.entity_type, observation.value, observation.source_url)
                )
                evidence_hash = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()
                connection.execute(
                    """
                    INSERT OR IGNORE INTO osint_observations
                    (investigation_id, collector, category, entity_type, value, source_url,
                     confidence, risk_points, metadata_json, evidence_hash, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        observation.collector,
                        observation.category,
                        observation.entity_type,
                        observation.value,
                        observation.source_url,
                        observation.confidence,
                        observation.risk_points,
                        json.dumps(observation.metadata, sort_keys=True),
                        evidence_hash,
                        utc_now(),
                    ),
                )
                if observation.entity_type == "SEARCH_RESULT":
                    self._save_search_source(connection, investigation_id, observation)
                elif observation.entity_type == "AUTOMATED_SOCIAL_FINDING":
                    self._save_social_finding(connection, investigation_id, observation)
                elif observation.entity_type == "PUBLIC_DOCUMENT":
                    self._save_document(connection, investigation_id, observation)

    @staticmethod
    def _save_social_finding(connection, investigation_id: str, observation: Observation) -> None:
        metadata = observation.metadata
        normalized_url = metadata.get("normalized_url") or observation.source_url
        connection.execute(
            """
            INSERT OR IGNORE INTO osint_social_findings
            (investigation_id, platform, post_url, normalized_post_url, title, post_text,
             matched_target, confidence, collector_method, query_id, search_engine,
             search_rank, status, screenshot_paths_json, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id, metadata.get("platform", "Unknown"), observation.source_url,
                normalized_url, metadata.get("title", observation.value),
                metadata.get("post_text", metadata.get("snippet", "")),
                metadata.get("matched_target_variant", ""), observation.confidence,
                metadata.get("collector_method", observation.collector),
                metadata.get("query_id", ""), metadata.get("search_engine", observation.collector),
                int(metadata.get("rank", 0)), metadata.get("status", "collected"),
                json.dumps(metadata.get("screenshot_paths", [])), utc_now(),
            ),
        )

    @staticmethod
    def _save_query_execution(
        connection,
        investigation_id: str,
        observation: Observation,
    ) -> None:
        metadata = observation.metadata
        connection.execute(
            """
            INSERT OR REPLACE INTO osint_query_executions
            (investigation_id, query_id, provider, raw_results, accepted_results,
             rejected_irrelevant, provider_semantic_quality, executed_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id, metadata["query_id"], metadata["provider"],
                int(metadata["raw_results"]), int(metadata["accepted_results"]),
                int(metadata["rejected_irrelevant"]), metadata["provider_semantic_quality"], utc_now(),
                metadata.get("status", "completed"),
            ),
        )

    @staticmethod
    def _save_search_result_audit(
        connection,
        investigation_id: str,
        observation: Observation,
    ) -> None:
        metadata = observation.metadata
        connection.execute(
            """
            INSERT OR IGNORE INTO osint_search_results
            (investigation_id, query_id, query_text, provider, search_rank, title,
             source_url, snippet, normalized_url, source_type, relevance_status,
             matched_target_variant, relevance_field, relevance_reason,
             provider_semantic_quality, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id, metadata.get("query_id", ""), metadata.get("query_text", ""),
                metadata.get("search_engine", observation.collector), int(metadata.get("rank", 0)),
                metadata.get("title", observation.value), observation.source_url,
                metadata.get("snippet", ""), metadata.get("normalized_url", ""),
                metadata.get("source_type", "unknown"), metadata.get("relevance_status", "accepted"),
                metadata.get("matched_target_variant", ""), metadata.get("relevance_field", ""),
                metadata.get("relevance_reason", ""), metadata.get("provider_semantic_quality", "partial"),
                utc_now(),
            ),
        )

    @staticmethod
    def _save_search_source(
        connection,
        investigation_id: str,
        observation: Observation,
    ) -> None:
        metadata = observation.metadata
        normalized_url = metadata.get("normalized_url")
        query_id = metadata.get("query_id")
        if not normalized_url or not query_id:
            return
        connection.execute(
            """
            INSERT OR IGNORE INTO osint_sources
            (investigation_id, normalized_url, source_url, title, snippet, source_type, first_seen_at,
             relevance_status, matched_target_variant, relevance_field, relevance_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                normalized_url,
                observation.source_url,
                metadata.get("title", observation.value),
                metadata.get("snippet", ""),
                metadata.get("source_type", "unknown"),
                utc_now(),
                metadata.get("relevance_status", "accepted"),
                metadata.get("matched_target_variant", ""),
                metadata.get("relevance_field", ""),
                metadata.get("relevance_reason", ""),
            ),
        )
        source_row = connection.execute(
            "SELECT id FROM osint_sources WHERE investigation_id = ? AND normalized_url = ?",
            (investigation_id, normalized_url),
        ).fetchone()
        if source_row:
            connection.execute(
                """
                INSERT OR IGNORE INTO osint_source_query_map
                (source_id, query_id, query_text, search_engine, search_rank)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    source_row["id"],
                    query_id,
                    metadata.get("query_text", ""),
                    metadata.get("search_engine", observation.collector),
                    int(metadata.get("rank", 0)),
                ),
            )

    @staticmethod
    def _save_document(
        connection,
        investigation_id: str,
        observation: Observation,
    ) -> None:
        metadata = observation.metadata
        if not metadata.get("artifact_path") or not metadata.get("sha256"):
            return
        artifact_path = Path(metadata["artifact_path"])
        try:
            content_blob = artifact_path.read_bytes()
        except OSError:
            content_blob = None
        connection.execute(
            """
            INSERT OR IGNORE INTO osint_documents
            (investigation_id, source_url, final_url, document_type, local_path,
             sha256, size_bytes, discovered_at, matched_target_variant,
             matched_keywords_json, relevant_pages_json, evidence_context, relevance_status,
             page_screenshots_json, file_name, media_type, content_blob,
             discovery_queries_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                observation.source_url,
                metadata.get("final_url"),
                metadata.get("document_type"),
                metadata["artifact_path"],
                metadata["sha256"],
                int(metadata.get("content_length", 0)),
                utc_now(),
                metadata.get("matched_target_variant", ""),
                json.dumps(metadata.get("matched_keywords", [])),
                json.dumps(metadata.get("relevant_pages", [])),
                metadata.get("evidence_context", ""),
                metadata.get("relevance_status", "confirmed_evidence"),
                json.dumps(metadata.get("page_screenshots", [])),
                metadata.get("file_name", artifact_path.name),
                metadata.get("media_type", "application/octet-stream"),
                content_blob,
                json.dumps(metadata.get("discovery_queries", [])),
            ),
        )

    def complete(self, investigation_id: str, assessment: RiskAssessment, status: str = "COMPLETED") -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE osint_investigations SET completed_at = ?, status = ?, risk_score = ?, risk_level = ?, risk_confidence = ? WHERE id = ?",
                (utc_now(), status, assessment.score, assessment.level, assessment.confidence, investigation_id),
            )
            connection.execute("DELETE FROM osint_risk_indicators WHERE investigation_id = ?", (investigation_id,))
            connection.executemany(
                """
                INSERT INTO osint_risk_indicators
                (investigation_id, category, indicator, value, points, confidence, source_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        investigation_id,
                        item["category"],
                        item["indicator"],
                        item["value"],
                        item["points"],
                        item["confidence"],
                        item["source_url"],
                    )
                    for item in assessment.indicators
                ],
            )

    def cancel(self, investigation_id: str) -> None:
        with self.connection() as connection:
            connection.execute(
                "UPDATE osint_investigations SET completed_at = ?, status = 'CANCELLED' WHERE id = ?",
                (utc_now(), investigation_id),
            )

    def list_investigations(self) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute("SELECT * FROM osint_investigations ORDER BY started_at DESC").fetchall()
        return [dict(row) for row in rows]

    def get_investigation(self, investigation_id: str) -> dict:
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM osint_investigations WHERE id = ?", (investigation_id,)).fetchone()
        return dict(row) if row else {}

    def get_observations(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM osint_observations WHERE investigation_id = ? ORDER BY category, id",
                (investigation_id,),
            ).fetchall()
        observations = []
        for row in rows:
            item = dict(row)
            try:
                metadata = json.loads(item.get("metadata_json") or "{}")
            except json.JSONDecodeError:
                metadata = {}
            item["query_id"] = metadata.get("query_id")
            item["search_rank"] = metadata.get("search_rank", metadata.get("rank"))
            item["source_title"] = metadata.get("source_title", metadata.get("title"))
            item["evidence_snippet"] = metadata.get("evidence_snippet", metadata.get("snippet"))
            item["source_type"] = metadata.get("source_type")
            item["target_keyword_distance"] = metadata.get("target_keyword_distance")
            item["target_relevance_confirmed"] = metadata.get("target_relevance_confirmed", False)
            item["relevance_status"] = metadata.get("relevance_status", "")
            observations.append(item)
        return observations

    def get_queries(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT query_id, category, name, priority, query, description, provider,
                       enabled, evidence_keywords_json, target_requirement, document_type
                FROM osint_queries WHERE investigation_id = ?
                ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, query_id
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_candidates(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT domain, confidence, reason, appearances, selected, domain_status, detailed_status,
                       http_status, final_url, response_time_ms, check_error, checked_at, monthly_visits,
                       yearly_visits, yearly_visits_kind, traffic_source, traffic_data_date
                FROM osint_target_candidates WHERE investigation_id = ?
                ORDER BY confidence DESC, appearances DESC
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def add_candidate_domains(self, investigation_id: str, domains: Iterable[str], reason: str = "Discovered related domain") -> None:
        with self.connection() as connection:
            connection.executemany(
                """INSERT OR IGNORE INTO osint_target_candidates
                   (investigation_id, domain, confidence, reason, appearances, selected)
                   VALUES (?, ?, ?, ?, ?, 0)""",
                [(investigation_id, domain, 0.35, reason, 1) for domain in domains],
            )

    def save_domain_checks(self, investigation_id: str, checks: Iterable[object]) -> None:
        fields = ("domain_status", "detailed_status", "http_status", "final_url", "response_time_ms", "error", "checked_at", "monthly_visits", "yearly_visits", "yearly_visits_kind", "traffic_source", "traffic_data_date")
        with self.connection() as connection:
            for check in checks:
                data = check.__dict__
                connection.execute(
                    """UPDATE osint_target_candidates SET domain_status=?, detailed_status=?, http_status=?, final_url=?,
                       response_time_ms=?, check_error=?, checked_at=?, monthly_visits=?, yearly_visits=?,
                       yearly_visits_kind=?, traffic_source=?, traffic_data_date=? WHERE investigation_id=? AND domain=?""",
                    tuple(data.get(field) for field in fields) + (investigation_id, data["domain"]),
                )
                connection.execute(
                    """INSERT OR REPLACE INTO osint_domain_traffic_cache
                       (domain, monthly_visits, yearly_visits, yearly_visits_kind, traffic_source, traffic_data_date, error, refreshed_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (data["domain"], data.get("monthly_visits"), data.get("yearly_visits"), data.get("yearly_visits_kind"),
                     data.get("traffic_source", "Unavailable"), data.get("traffic_data_date"), data.get("error"), data.get("checked_at")),
                )

    def get_traffic_cache(self, domains: Iterable[str]) -> dict[str, dict]:
        names = list(dict.fromkeys(domains))
        if not names:
            return {}
        marks = ",".join("?" for _ in names)
        with self.connection() as connection:
            rows = connection.execute(f"SELECT * FROM osint_domain_traffic_cache WHERE domain IN ({marks})", names).fetchall()
        return {row["domain"]: dict(row) for row in rows}

    def get_candidate_leads(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT value AS domain, source_url, confidence, metadata_json, discovered_at
                   FROM osint_observations
                   WHERE investigation_id = ? AND entity_type = 'CANDIDATE_DOMAIN'
                   ORDER BY confidence DESC, id""",
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_search_identities(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT value, identity_type, confidence, reason
                   FROM osint_search_identities WHERE investigation_id = ?
                   ORDER BY confidence DESC, id""",
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_social_findings(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, platform, post_url, title, post_text, matched_target,
                       confidence, collector_method, query_id, search_engine,
                       search_rank, status, screenshot_paths_json, collected_at
                FROM osint_social_findings
                WHERE investigation_id = ?
                ORDER BY platform, search_rank, id
                """,
                (investigation_id,),
            ).fetchall()
        findings = [dict(row) for row in rows]
        for finding in findings:
            finding["screenshot_paths"] = json.loads(finding.pop("screenshot_paths_json") or "[]")
        return findings

    def get_sources(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT s.id, s.source_url, s.normalized_url, s.title, s.snippet, s.source_type,
                       s.first_seen_at, COUNT(m.id) AS discovered_by_queries,
                       MIN(m.search_rank) AS best_rank,
                       MAX(CASE WHEN q.document_type IS NOT NULL AND q.document_type != '' THEN 1 ELSE 0 END) AS document_priority
                FROM osint_sources s
                LEFT JOIN osint_source_query_map m ON m.source_id = s.id
                LEFT JOIN osint_queries q ON q.investigation_id = s.investigation_id AND q.query_id = m.query_id
                WHERE s.investigation_id = ? AND s.relevance_status = 'accepted'
                GROUP BY s.id
                ORDER BY document_priority DESC, best_rank, s.id
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_document_sources(self, investigation_id: str, limit: int = 25) -> list[dict]:
        """Return accepted document leads across every query, with provenance."""
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT s.id, s.source_url, s.normalized_url, s.title, s.snippet,
                       s.source_type, s.first_seen_at, MIN(m.search_rank) AS best_rank
                FROM osint_sources s
                LEFT JOIN osint_source_query_map m ON m.source_id = s.id
                WHERE s.investigation_id = ? AND s.relevance_status = 'accepted'
                  AND (
                    s.source_type IN ('pdf_document', 'other_document')
                    OR EXISTS (
                      SELECT 1 FROM osint_source_query_map dm
                      JOIN osint_queries q
                        ON q.investigation_id = s.investigation_id
                       AND q.query_id = dm.query_id
                      WHERE dm.source_id = s.id
                        AND q.document_type IS NOT NULL AND q.document_type != ''
                    )
                  )
                  AND (
                    s.source_type IN ('pdf_document', 'other_document')
                    OR LOWER(COALESCE(s.source_url, '')) LIKE '%%.pdf%%'
                    OR LOWER(COALESCE(s.source_url, '')) LIKE '%%.docx%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%pdf%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%document%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%certificate%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%licence%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%license%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%pdf%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%document%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%certificate%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%licence%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%license%%'
                  )
                GROUP BY s.id
                ORDER BY best_rank, s.id
                LIMIT ?
                """,
                (investigation_id, max(0, limit)),
            ).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                mappings = connection.execute(
                    """
                    SELECT m.query_id, m.query_text, m.search_engine, m.search_rank,
                           COALESCE(q.evidence_keywords_json, '[]') AS evidence_keywords_json
                    FROM osint_source_query_map m
                    LEFT JOIN osint_queries q
                      ON q.investigation_id = ? AND q.query_id = m.query_id
                    WHERE m.source_id = ?
                    ORDER BY m.search_rank, m.query_id, m.search_engine
                    """,
                    (investigation_id, item["id"]),
                ).fetchall()
                item["discovery_queries"] = []
                for mapping in mappings:
                    query = dict(mapping)
                    try:
                        query["evidence_keywords"] = json.loads(
                            query.pop("evidence_keywords_json") or "[]"
                        )
                    except json.JSONDecodeError:
                        query["evidence_keywords"] = []
                    item["discovery_queries"].append(query)
                items.append(item)
        return items

    def get_evidence_tasks(self, investigation_id: str, limit: int = 8) -> list[dict]:
        """Return deduplicated pages with every SERP query that discovered each page."""
        with self.connection() as connection:
            source_rows = connection.execute(
                """
                SELECT s.id AS source_id, s.source_url, s.normalized_url, s.source_type, s.title, s.snippet,
                       MAX(CASE WHEN q.document_type IS NOT NULL AND q.document_type != '' THEN 1 ELSE 0 END) AS document_priority,
                       MIN(m.search_rank) AS best_rank
                FROM osint_sources s
                LEFT JOIN osint_source_query_map m ON m.source_id = s.id
                LEFT JOIN osint_queries q ON q.investigation_id = s.investigation_id AND q.query_id = m.query_id
                WHERE s.investigation_id = ? AND s.relevance_status = 'accepted'
                GROUP BY s.id
                ORDER BY document_priority DESC, best_rank, s.id
                LIMIT ?
                """,
                (investigation_id, max(0, limit)),
            ).fetchall()
            tasks = []
            for source in source_rows:
                mappings = connection.execute(
                    """
                    SELECT m.query_id, q.name AS query_name, q.category AS query_category,
                           m.search_engine, m.search_rank,
                           COALESCE(q.document_type, '') AS document_type,
                           COALESCE(q.evidence_keywords_json,
                             '["deposit", "withdrawal", "payment", "wallet", "betting", "casino", "complaint", "licence", "license", "registration", "APK"]'
                           ) AS evidence_keywords_json
                    FROM osint_source_query_map m
                    LEFT JOIN osint_queries q
                      ON q.investigation_id = ? AND q.query_id = m.query_id
                    WHERE m.source_id = ?
                    ORDER BY m.search_rank, m.query_id
                    """,
                    (investigation_id, source["source_id"]),
                ).fetchall()
                query_items = []
                for mapping in mappings:
                    item = dict(mapping)
                    item["query_name"] = item.get("query_name") or "Historical public URL"
                    item["query_category"] = item.get("query_category") or "historical_discovery"
                    try:
                        item["evidence_keywords"] = json.loads(item.pop("evidence_keywords_json") or "[]")
                    except json.JSONDecodeError:
                        item["evidence_keywords"] = []
                    query_items.append(item)
                if query_items:
                    task = dict(source)
                    task["queries"] = query_items
                    tasks.append(task)
        return tasks

    def get_document_capture_tasks(self, investigation_id: str) -> list[dict]:
        """Return every accepted target-related result matching a document query and document signal."""
        with self.connection() as connection:
            source_rows = connection.execute(
                """
                SELECT DISTINCT s.id AS source_id, s.source_url, s.normalized_url,
                       s.source_type, s.title, s.snippet, 1 AS document_priority,
                       MIN(m.search_rank) AS best_rank
                FROM osint_sources s
                JOIN osint_source_query_map m ON m.source_id = s.id
                JOIN osint_queries q
                  ON q.investigation_id = s.investigation_id AND q.query_id = m.query_id
                WHERE s.investigation_id = ?
                  AND s.relevance_status = 'accepted'
                  AND q.document_type IS NOT NULL AND q.document_type != ''
                  AND (
                    s.source_type IN ('pdf_document', 'other_document')
                    OR LOWER(COALESCE(s.source_url, '')) LIKE '%%.pdf%%'
                    OR LOWER(COALESCE(s.source_url, '')) LIKE '%%.docx%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%pdf%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%document%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%certificate%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%licence%%'
                    OR LOWER(COALESCE(s.title, '')) LIKE '%%license%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%pdf%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%document%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%certificate%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%licence%%'
                    OR LOWER(COALESCE(s.snippet, '')) LIKE '%%license%%'
                  )
                GROUP BY s.id
                ORDER BY best_rank, s.id
                """,
                (investigation_id,),
            ).fetchall()
            tasks = []
            for source in source_rows:
                mappings = connection.execute(
                    """
                    SELECT m.query_id, q.name AS query_name, q.category AS query_category,
                           m.search_engine, m.search_rank, q.document_type,
                           COALESCE(q.evidence_keywords_json, '[]') AS evidence_keywords_json
                    FROM osint_source_query_map m
                    JOIN osint_queries q
                      ON q.investigation_id = ? AND q.query_id = m.query_id
                    WHERE m.source_id = ?
                      AND q.document_type IS NOT NULL AND q.document_type != ''
                    ORDER BY m.search_rank, m.query_id
                    """,
                    (investigation_id, source["source_id"]),
                ).fetchall()
                queries = []
                for mapping in mappings:
                    item = dict(mapping)
                    try:
                        item["evidence_keywords"] = json.loads(item.pop("evidence_keywords_json") or "[]")
                    except json.JSONDecodeError:
                        item["evidence_keywords"] = []
                    queries.append(item)
                if queries:
                    task = dict(source)
                    task["queries"] = queries
                    tasks.append(task)
        return tasks

    def save_page_captures(self, investigation_id: str, records: Iterable[PageCaptureRecord]) -> None:
        with self.connection() as connection:
            for record in records:
                connection.execute(
                    """
                    INSERT INTO osint_page_captures
                    (investigation_id, source_id, source_url, final_url, page_title,
                     http_status, accessibility_status, failure_reason, captured_at,
                     matched_target_variant, relevance_field)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(investigation_id, source_id) DO UPDATE SET
                      final_url=excluded.final_url, page_title=excluded.page_title,
                      http_status=excluded.http_status,
                      accessibility_status=excluded.accessibility_status,
                      failure_reason=excluded.failure_reason, captured_at=excluded.captured_at,
                      matched_target_variant=excluded.matched_target_variant,
                      relevance_field=excluded.relevance_field
                    """,
                    (
                        investigation_id, record.source_id, record.source_url, record.final_url,
                        record.page_title, record.http_status, record.accessibility_status,
                        record.failure_reason, utc_now(), record.matched_target_variant,
                        record.relevance_field,
                    ),
                )
                capture_id = connection.execute(
                    "SELECT id FROM osint_page_captures WHERE investigation_id = ? AND source_id = ?",
                    (investigation_id, record.source_id),
                ).fetchone()["id"]
                connection.execute(
                    "DELETE FROM osint_evidence_screenshots WHERE evidence_match_id IN (SELECT id FROM osint_evidence_matches WHERE page_capture_id = ?)",
                    (capture_id,),
                )
                connection.execute("DELETE FROM osint_evidence_matches WHERE page_capture_id = ?", (capture_id,))
                connection.execute(
                    "DELETE FROM osint_document_page_captures WHERE investigation_id = ? AND source_id = ?",
                    (investigation_id, record.source_id),
                )
                for evidence in record.screenshots:
                    cursor = connection.execute(
                        """
                        INSERT INTO osint_evidence_matches
                        (page_capture_id, query_id, query_name, query_category, search_engine,
                         serp_rank, matched_keywords_json, matched_phrases_json, evidence_text,
                         context_text, match_method, confidence, matched_target_variant,
                         target_keyword_distance)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            capture_id, evidence.query_id, evidence.query_name,
                            evidence.query_category, evidence.search_engine, evidence.serp_rank,
                            json.dumps(evidence.matched_keywords), json.dumps(evidence.matched_phrases),
                            evidence.evidence_text, evidence.context_text, evidence.match_method,
                            evidence.confidence, evidence.matched_target_variant,
                            evidence.target_keyword_distance,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO osint_evidence_screenshots
                        (evidence_match_id, screenshot_path, sha256, captured_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (cursor.lastrowid, evidence.screenshot_path, evidence.screenshot_sha256, utc_now()),
                    )
                    if evidence.match_method == "document_viewer_page" and evidence.document_page_number:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO osint_document_page_captures
                            (investigation_id, source_id, query_id, query_name, search_engine,
                             source_url, final_url, page_number, screenshot_path, sha256, captured_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                investigation_id, record.source_id, evidence.query_id,
                                evidence.query_name, evidence.search_engine, record.source_url,
                                record.final_url, evidence.document_page_number,
                                evidence.screenshot_path, evidence.screenshot_sha256, utc_now(),
                            ),
                        )
                lifecycle_status = {
                    "evidence_found": "confirmed_evidence",
                    "baseline_captured": "target_baseline",
                    "document_viewer_captured": "document_viewer_capture",
                    "no_evidence": "no_evidence",
                    "manual_required": "manual_required",
                    "rejected_irrelevant": "rejected_irrelevant",
                    "failed": "failed",
                }.get(record.accessibility_status, record.accessibility_status)
                connection.execute(
                    """
                    UPDATE osint_search_results
                    SET relevance_status = ?, relevance_reason = COALESCE(?, relevance_reason)
                    WHERE investigation_id = ? AND normalized_url = (
                        SELECT normalized_url FROM osint_sources WHERE id = ?
                    )
                    """,
                    (lifecycle_status, record.failure_reason, investigation_id, record.source_id),
                )

    def get_evidence(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT e.id, p.source_id, p.source_url, p.final_url, p.page_title,
                       p.http_status, p.accessibility_status, e.query_id, e.query_name,
                       e.query_category, e.search_engine, e.serp_rank,
                       e.matched_keywords_json, e.matched_phrases_json, e.evidence_text,
                       e.context_text, e.match_method, e.confidence,
                       e.matched_target_variant, e.target_keyword_distance,
                       s.source_type, shot.screenshot_path, shot.sha256, shot.captured_at
                FROM osint_evidence_matches e
                JOIN osint_page_captures p ON p.id = e.page_capture_id
                JOIN osint_sources s ON s.id = p.source_id
                JOIN osint_evidence_screenshots shot ON shot.evidence_match_id = e.id
                WHERE p.investigation_id = ?
                ORDER BY e.serp_rank, e.query_id, e.id
                """,
                (investigation_id,),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            for source, target in (("matched_keywords_json", "matched_keywords"), ("matched_phrases_json", "matched_phrases")):
                try:
                    item[target] = json.loads(item.pop(source) or "[]")
                except json.JSONDecodeError:
                    item[target] = []
            items.append(item)
        return items

    def get_document_viewer_captures(self, investigation_id: str) -> list[dict]:
        """Return screenshots from public HTML document viewers for the Documents tab."""
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT d.id AS capture_id, d.source_id, d.source_url, d.final_url, p.page_title,
                       d.query_id, d.query_name, d.search_engine,
                       d.page_number, ('Public document viewer page ' || d.page_number) AS evidence_text,
                       d.screenshot_path, d.sha256, d.captured_at
                FROM osint_document_page_captures d
                LEFT JOIN osint_page_captures p
                  ON p.investigation_id = d.investigation_id AND p.source_id = d.source_id
                WHERE d.investigation_id = ?
                ORDER BY d.source_id, d.query_id, d.page_number
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_page_captures(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT p.source_id, p.source_url, p.final_url, p.page_title, p.http_status,
                       p.accessibility_status, p.failure_reason, p.captured_at, s.source_type
                FROM osint_page_captures p
                JOIN osint_sources s ON s.id = p.source_id
                WHERE p.investigation_id = ? ORDER BY p.id
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_rejected_search_results(self, investigation_id: str, limit: int = 250) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT query_id, provider, search_rank, title, source_url, snippet,
                       source_type, relevance_status, relevance_reason, discovered_at
                FROM osint_search_results
                WHERE investigation_id = ? AND relevance_status = 'rejected_irrelevant'
                ORDER BY query_id, search_rank LIMIT ?
                """,
                (investigation_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_query_metrics(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT q.query_id, q.category, q.name, q.priority, q.query,
                       MAX(x.provider) AS provider,
                       COALESCE(MAX(x.raw_results), 0) AS raw_results,
                       COALESCE(MAX(x.accepted_results), 0) AS accepted_results,
                       COALESCE(MAX(x.rejected_irrelevant), 0) AS rejected_results,
                       COUNT(DISTINCT s.id) AS unique_urls,
                       COUNT(DISTINCT p.id) AS pages_visited,
                       COUNT(DISTINCT e.id) AS evidence_matches,
                       COUNT(DISTINCT shot.id) AS screenshots,
                       (COUNT(DISTINCT CASE WHEN p.accessibility_status = 'manual_required' THEN p.id END) +
                        MAX(CASE WHEN x.status = 'manual_required' THEN 1 ELSE 0 END)) AS manual_required,
                       COUNT(DISTINCT CASE WHEN p.accessibility_status = 'failed' THEN p.id END) AS failed
                FROM osint_queries q
                LEFT JOIN osint_source_query_map m ON m.query_id = q.query_id
                LEFT JOIN osint_query_executions x
                  ON x.investigation_id = q.investigation_id AND x.query_id = q.query_id
                LEFT JOIN osint_sources s ON s.id = m.source_id AND s.investigation_id = q.investigation_id
                LEFT JOIN osint_page_captures p ON p.source_id = s.id
                LEFT JOIN osint_evidence_matches e ON e.page_capture_id = p.id AND e.query_id = q.query_id
                LEFT JOIN osint_evidence_screenshots shot ON shot.evidence_match_id = e.id
                WHERE q.investigation_id = ?
                GROUP BY q.id
                ORDER BY CASE q.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, q.query_id
                """,
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_summary_counts(self, investigation_id: str) -> dict:
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM osint_queries WHERE investigation_id = ?) AS configured_queries,
                  (SELECT COUNT(*) FROM osint_search_results WHERE investigation_id = ?) AS raw_search_results,
                  (SELECT COUNT(*) FROM osint_sources WHERE investigation_id = ? AND relevance_status = 'accepted') AS accepted_sources,
                  (SELECT COUNT(*) FROM osint_search_results WHERE investigation_id = ? AND relevance_status = 'rejected_irrelevant') AS rejected_irrelevant,
                  (SELECT COUNT(*) FROM osint_page_captures WHERE investigation_id = ?) AS pages_visited,
                  (SELECT COUNT(*) FROM osint_evidence_matches e JOIN osint_page_captures p ON p.id = e.page_capture_id WHERE p.investigation_id = ?) AS confirmed_evidence,
                  (SELECT COUNT(*) FROM osint_documents WHERE investigation_id = ? AND relevance_status = 'confirmed_evidence') AS public_documents,
                  (SELECT COUNT(*) FROM osint_evidence_screenshots s JOIN osint_evidence_matches e ON e.id = s.evidence_match_id JOIN osint_page_captures p ON p.id = e.page_capture_id WHERE p.investigation_id = ?) AS screenshots_captured,
                  ((SELECT COUNT(*) FROM osint_page_captures WHERE investigation_id = ? AND accessibility_status = 'manual_required') +
                   (SELECT COUNT(*) FROM osint_observations WHERE investigation_id = ? AND entity_type = 'SEARCH_PROVIDER_MANUAL_REQUIRED')) AS manual_required,
                  (SELECT COUNT(*) FROM osint_page_captures WHERE investigation_id = ? AND accessibility_status = 'failed') AS failures
                """,
                (investigation_id,) * 11,
            ).fetchone()
        return dict(row)

    def get_query_results(self, investigation_id: str, query_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT m.search_rank AS rank, s.title, s.source_url, s.source_type,
                       COALESCE(p.accessibility_status, 'not_visited') AS status,
                       COUNT(DISTINCT e.id) AS evidence_matches,
                       COUNT(DISTINCT shot.id) AS screenshot_count
                FROM osint_source_query_map m
                JOIN osint_sources s ON s.id = m.source_id
                LEFT JOIN osint_page_captures p ON p.source_id = s.id
                LEFT JOIN osint_evidence_matches e ON e.page_capture_id = p.id AND e.query_id = m.query_id
                LEFT JOIN osint_evidence_screenshots shot ON shot.evidence_match_id = e.id
                WHERE s.investigation_id = ? AND m.query_id = ?
                GROUP BY m.id, m.search_rank, s.id, s.title, s.source_url,
                         s.source_type, p.accessibility_status
                ORDER BY m.search_rank, s.id
                """,
                (investigation_id, query_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_documents(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT id, source_url, final_url, document_type, local_path, sha256,
                       size_bytes, discovered_at, matched_target_variant,
                       matched_keywords_json, relevant_pages_json, evidence_context,
                       relevance_status, page_screenshots_json, file_name, media_type,
                       discovery_queries_json
                FROM osint_documents WHERE investigation_id = ? ORDER BY id
                """,
                (investigation_id,),
            ).fetchall()
        documents = []
        for row in rows:
            item = dict(row)
            for source, target in (("matched_keywords_json", "matched_keywords"), ("relevant_pages_json", "relevant_pages")):
                try:
                    item[target] = json.loads(item.pop(source) or "[]")
                except json.JSONDecodeError:
                    item[target] = []
            try:
                item["page_screenshots"] = json.loads(item.pop("page_screenshots_json") or "[]")
            except json.JSONDecodeError:
                item["page_screenshots"] = []
            try:
                item["discovery_queries"] = json.loads(item.pop("discovery_queries_json") or "[]")
            except json.JSONDecodeError:
                item["discovery_queries"] = []
            documents.append(item)
        return documents

    def get_document_content(self, investigation_id: str, document_id: int) -> bytes | None:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT content_blob FROM osint_documents WHERE investigation_id = ? AND id = ?",
                (investigation_id, document_id),
            ).fetchone()
        if not row or row["content_blob"] is None:
            return None
        return bytes(row["content_blob"])

    def add_analyst_note(self, investigation_id: str, note: str) -> None:
        cleaned = note.strip()
        if not cleaned:
            raise ValueError("Analyst note cannot be empty.")
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO osint_analyst_notes (investigation_id, note, created_at) VALUES (?, ?, ?)",
                (investigation_id, cleaned, utc_now()),
            )

    def get_analyst_notes(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT note, created_at FROM osint_analyst_notes WHERE investigation_id = ? ORDER BY id",
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_collector_runs(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT collector, status, duration_seconds, observation_count, error FROM osint_collector_runs WHERE investigation_id = ? ORDER BY id",
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_risk_indicators(self, investigation_id: str) -> list[dict]:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT category, indicator, value, points, confidence, source_url FROM osint_risk_indicators WHERE investigation_id = ? ORDER BY points DESC",
                (investigation_id,),
            ).fetchall()
        return [dict(row) for row in rows]
