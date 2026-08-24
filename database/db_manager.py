import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from config import DB_PATH

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = str(db_path)
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Creates the 7 required database tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Investigations Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    website_url TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration REAL DEFAULT 0.0,
                    login_required BOOLEAN DEFAULT 0,
                    total_pages INTEGER DEFAULT 0,
                    investigation_status TEXT DEFAULT 'RUNNING'
                )
            """)
            
            # 2. Pages Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pages (
                    page_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    page_title TEXT,
                    page_url TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    visited_time TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                )
            """)

            # 3. Keyword Findings Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keyword_findings (
                    keyword_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_id INTEGER NOT NULL,
                    keyword TEXT NOT NULL,
                    category TEXT NOT NULL,
                    count INTEGER DEFAULT 1,
                    bounding_box TEXT,
                    FOREIGN KEY (page_id) REFERENCES pages (page_id)
                )
            """)

            # 4. Screenshots Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS screenshots (
                    screenshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_id INTEGER NOT NULL,
                    highlighted_image_path TEXT NOT NULL,
                    captured_time TEXT NOT NULL,
                    FOREIGN KEY (page_id) REFERENCES pages (page_id)
                )
            """)

            # 5. Payment Findings Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payment_findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    page_id INTEGER NOT NULL,
                    finding_type TEXT NOT NULL,
                    finding_value TEXT NOT NULL,
                    confidence TEXT DEFAULT 'High',
                    FOREIGN KEY (page_id) REFERENCES pages (page_id)
                )
            """)

            # 6. Navigation Graph Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS navigation_graph (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    parent_page TEXT NOT NULL,
                    child_page TEXT NOT NULL,
                    navigation_depth INTEGER DEFAULT 0,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                )
            """)

            # 7. Crawl Logs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS crawl_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                )
            """)

            conn.commit()

    # --- Investigation Operations ---
    def create_investigation(self, investigation_id: str, website_url: str) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO investigations (id, website_url, start_time, investigation_status)
                VALUES (?, ?, ?, 'RUNNING')
            """, (investigation_id, website_url, now))
            conn.commit()
        return investigation_id

    def update_investigation(self, investigation_id: str, status: str, duration: float = 0.0, 
                             total_pages: int = 0, login_required: bool = False):
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE investigations 
                SET investigation_status = ?, end_time = ?, duration = ?, 
                    total_pages = ?, login_required = ?
                WHERE id = ?
            """, (status, end_time, duration, total_pages, 1 if login_required else 0, investigation_id))
            conn.commit()

    # --- Page Operations ---
    def add_page(self, investigation_id: str, page_url: str, page_title: str, priority: str) -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pages (investigation_id, page_url, page_title, priority, visited_time)
                VALUES (?, ?, ?, ?, ?)
            """, (investigation_id, page_url, page_title, priority, now))
            conn.commit()
            return cursor.lastrowid

    # --- Evidence Insertion Operations ---
    def add_keyword_findings(self, page_id: int, findings: List[Dict[str, Any]]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for item in findings:
                bbox_json = json.dumps(item.get("bounding_box", {}))
                cursor.execute("""
                    INSERT INTO keyword_findings (page_id, keyword, category, count, bounding_box)
                    VALUES (?, ?, ?, ?, ?)
                """, (page_id, item["keyword"], item["category"], item.get("count", 1), bbox_json))
            conn.commit()

    def add_screenshot(self, page_id: int, image_path: str) -> int:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO screenshots (page_id, highlighted_image_path, captured_time)
                VALUES (?, ?, ?)
            """, (page_id, image_path, now))
            conn.commit()
            return cursor.lastrowid

    def add_payment_findings(self, page_id: int, findings: List[Dict[str, Any]]):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for item in findings:
                cursor.execute("""
                    INSERT INTO payment_findings (page_id, finding_type, finding_value, confidence)
                    VALUES (?, ?, ?, ?)
                """, (page_id, item["finding_type"], item["finding_value"], item.get("confidence", "High")))
            conn.commit()

    def add_navigation_link(self, investigation_id: str, parent_page: str, child_page: str, depth: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO navigation_graph (investigation_id, parent_page, child_page, navigation_depth)
                VALUES (?, ?, ?, ?)
            """, (investigation_id, parent_page, child_page, depth))
            conn.commit()

    def log_action(self, investigation_id: str, action: str, status: str = "INFO"):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO crawl_logs (investigation_id, timestamp, action, status)
                VALUES (?, ?, ?, ?)
            """, (investigation_id, now, action, status))
            conn.commit()

    # --- Query Operations for Dashboard ---
    def get_latest_investigation(self) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigations ORDER BY start_time DESC LIMIT 1")
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_investigations(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigations ORDER BY start_time DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_investigation_summary(self, investigation_id: str) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Base Investigation info
            cursor.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
            inv = dict(cursor.fetchone() or {})

            # Pages count
            cursor.execute("SELECT COUNT(*) as total FROM pages WHERE investigation_id = ?", (investigation_id,))
            pages_count = cursor.fetchone()["total"]

            # Screenshots count
            cursor.execute("""
                SELECT COUNT(*) as total FROM screenshots s
                JOIN pages p ON s.page_id = p.page_id
                WHERE p.investigation_id = ?
            """, (investigation_id,))
            screenshots_count = cursor.fetchone()["total"]

            # Keyword counts by category
            cursor.execute("""
                SELECT category, SUM(count) as total FROM keyword_findings k
                JOIN pages p ON k.page_id = p.page_id
                WHERE p.investigation_id = ?
                GROUP BY category
            """, (investigation_id,))
            keyword_cats = {row["category"]: row["total"] for row in cursor.fetchall()}

            # Payment findings count
            cursor.execute("""
                SELECT COUNT(*) as total FROM payment_findings pf
                JOIN pages p ON pf.page_id = p.page_id
                WHERE p.investigation_id = ?
            """, (investigation_id,))
            payment_count = cursor.fetchone()["total"]

            return {
                "investigation": inv,
                "pages_visited": pages_count,
                "screenshots_captured": screenshots_count,
                "keyword_categories": keyword_cats,
                "financial_keywords": keyword_cats.get("Financial", 0),
                "gaming_keywords": keyword_cats.get("Gaming", 0),
                "payment_findings_count": payment_count
            }

    def get_pages_with_evidence(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Returns all pages for an investigation with their attached keywords, payments, and screenshots."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.*, s.highlighted_image_path, s.captured_time
                FROM pages p
                LEFT JOIN screenshots s ON p.page_id = s.page_id
                WHERE p.investigation_id = ?
                ORDER BY p.page_id ASC
            """, (investigation_id,))
            pages = [dict(row) for row in cursor.fetchall()]

            for p in pages:
                page_id = p["page_id"]
                
                # Fetch keywords
                cursor.execute("SELECT * FROM keyword_findings WHERE page_id = ?", (page_id,))
                p["keywords"] = [dict(r) for r in cursor.fetchall()]

                # Fetch payment findings
                cursor.execute("SELECT * FROM payment_findings WHERE page_id = ?", (page_id,))
                p["payment_findings"] = [dict(r) for r in cursor.fetchall()]

            return pages

    def get_payment_findings_all(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Returns detailed payment findings joined with page URLs for the Payment Intelligence tab."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT pf.*, p.page_url, p.page_title, p.priority
                FROM payment_findings pf
                JOIN pages p ON pf.page_id = p.page_id
                WHERE p.investigation_id = ?
                ORDER BY pf.finding_id ASC
            """, (investigation_id,))
            return [dict(row) for row in cursor.fetchall()]

    def get_table_data(self, table_name: str) -> List[Dict[str, Any]]:
        """Allows direct querying of any SQLite table for the built-in Database Inspector."""
        allowed_tables = ["investigations", "pages", "keyword_findings", "screenshots", 
                          "payment_findings", "navigation_graph", "crawl_logs"]
        if table_name not in allowed_tables:
            return []
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            return [dict(row) for row in cursor.fetchall()]
