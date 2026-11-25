"""数据层——SQLite 模型"""

import os
import sqlite3
import time
from typing import Optional


class Database:
    """数据库连接管理"""

    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, timeout=5)  # 5秒超时，避免死等
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def initialize(self) -> None:
        """创建所有表"""
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS analysis_cache (
            file_path       TEXT NOT NULL,
            mtime           INTEGER NOT NULL,
            size_bytes      INTEGER NOT NULL,
            decision        TEXT NOT NULL,
            confidence      REAL,
            reason          TEXT,
            risk            TEXT DEFAULT 'none',
            cluster_id      TEXT,
            analyzed_at     INTEGER NOT NULL,
            ai_model        TEXT DEFAULT 'unknown',
            PRIMARY KEY (file_path, mtime, size_bytes)
        );

        CREATE TABLE IF NOT EXISTS rules (
            pattern         TEXT PRIMARY KEY,
            decision        TEXT NOT NULL,
            confidence      REAL DEFAULT 0.9,
            priority        INTEGER DEFAULT 0,
            source          TEXT DEFAULT 'builtin',
            hit_count       INTEGER DEFAULT 0,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_path       TEXT NOT NULL,
            file_count      INTEGER DEFAULT 0,
            analyzed_count  INTEGER DEFAULT 0,
            cleaned_count   INTEGER DEFAULT 0,
            bytes_freed     INTEGER DEFAULT 0,
            started_at      INTEGER NOT NULL,
            finished_at     INTEGER,
            status          TEXT DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS pe_imports (
            importer_path   TEXT NOT NULL,
            imported_dll    TEXT NOT NULL,
            PRIMARY KEY (importer_path, imported_dll)
        );

        CREATE TABLE IF NOT EXISTS clean_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cleaned_count   INTEGER DEFAULT 0,
            bytes_moved     INTEGER DEFAULT 0,
            bytes_freed     INTEGER DEFAULT 0,
            created_at      INTEGER NOT NULL
        );
        """)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_rule(
        self,
        pattern: str,
        decision: str,
        confidence: float,
        source: str,
        priority: int = 0,
    ) -> None:
        """保存或更新规则"""
        now = int(time.time())
        self._conn.execute(
            """INSERT OR REPLACE INTO rules (pattern, decision, confidence, priority, source, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM rules WHERE pattern=?), ?), ?)""",
            (pattern, decision, confidence, priority, source, pattern, now, now),
        )
        self._conn.commit()

    def get_rules(self, source: Optional[str] = None) -> list[dict]:
        """获取规则列表"""
        if source:
            rows = self._conn.execute(
                "SELECT * FROM rules WHERE source=? ORDER BY priority DESC", (source,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM rules ORDER BY priority DESC"
            ).fetchall()
        return [dict(r) for r in rows]


class AnalysisCache:
    """分析结果缓存"""

    def __init__(self, db: Database):
        self._db = db

    def upsert(
        self,
        file_path: str,
        mtime: int,
        size_bytes: int,
        decision: str,
        confidence: float,
        reason: str,
        risk: str,
        ai_model: str,
        cluster_id: Optional[str] = None,
    ) -> None:
        """写入或更新缓存"""
        now = int(time.time())
        self._db._conn.execute(
            """INSERT OR REPLACE INTO analysis_cache
               (file_path, mtime, size_bytes, decision, confidence, reason, risk, cluster_id, analyzed_at, ai_model)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (file_path, mtime, size_bytes, decision, confidence, reason, risk, cluster_id, now, ai_model),
        )
        self._db._conn.commit()

    def get(self, file_path: str, mtime: int, size_bytes: int) -> Optional[dict]:
        """查询单条缓存"""
        row = self._db._conn.execute(
            """SELECT * FROM analysis_cache
               WHERE file_path=? AND mtime=? AND size_bytes=?""",
            (file_path, mtime, size_bytes),
        ).fetchone()
        return dict(row) if row else None

    def batch_get(self, keys: list[tuple[str, int, int]]) -> list[dict]:
        """批量查询缓存"""
        if not keys:
            return []
        placeholders = ", ".join(["(?, ?, ?)"] * len(keys))
        flat_keys = [v for key in keys for v in key]
        rows = self._db._conn.execute(
            f"""SELECT * FROM analysis_cache
                WHERE (file_path, mtime, size_bytes) IN ({placeholders})""",
            flat_keys,
        ).fetchall()
        return [dict(r) for r in rows]

    def purge_orphaned(self, existing_paths: dict | set) -> None:
        """清理已被删除文件的缓存（existing_paths 是当前磁盘上存在的路径集合）"""
        if not existing_paths:
            return
        # 从缓存中找出所有路径，删除不在 existing_paths 中的条目
        rows = self._db._conn.execute("SELECT DISTINCT file_path FROM analysis_cache").fetchall()
        for (fp,) in rows:
            if fp not in existing_paths:
                self._db._conn.execute("DELETE FROM analysis_cache WHERE file_path=?", (fp,))
        self._db._conn.commit()


class ScanRecord:
    """扫描记录管理"""

    def __init__(self, db: Database):
        self._db = db

    def start_scan(self, path: str, file_count: int) -> int:
        """创建新扫描记录，返回记录 ID"""
        now = int(time.time())
        cursor = self._db._conn.execute(
            """INSERT INTO scan_records (scan_path, file_count, started_at, status)
               VALUES (?, ?, ?, 'running')""",
            (path, file_count, now),
        )
        self._db._conn.commit()
        return cursor.lastrowid

    def finish_scan(
        self,
        scan_id: int,
        analyzed_count: int,
        cleaned_count: int,
        bytes_freed: int,
    ) -> None:
        """完成扫描记录"""
        now = int(time.time())
        self._db._conn.execute(
            """UPDATE scan_records
               SET analyzed_count=?, cleaned_count=?, bytes_freed=?, finished_at=?, status='completed'
               WHERE id=?""",
            (analyzed_count, cleaned_count, bytes_freed, now, scan_id),
        )
        self._db._conn.commit()

    def get_history(self, limit: int = 10) -> list[dict]:
        """获取最近扫描历史"""
        rows = self._db._conn.execute(
            "SELECT * FROM scan_records ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def record_cleanup(self, cleaned_count: int, bytes_moved: int = 0, bytes_freed: int = 0) -> int:
        """记录一次清理操作（与扫描记录分开，避免污染扫描次数）。"""
        now = int(time.time())
        cursor = self._db._conn.execute(
            """INSERT INTO clean_records (cleaned_count, bytes_moved, bytes_freed, created_at)
               VALUES (?, ?, ?, ?)""",
            (cleaned_count, bytes_moved, bytes_freed, now),
        )
        self._db._conn.commit()
        return cursor.lastrowid

    def get_total_stats(self) -> dict:
        """获取累计统计（扫描记录 + 清理记录）"""
        row = self._db._conn.execute(
            """SELECT
                 (SELECT COUNT(*) FROM scan_records WHERE status='completed') as total_scans,
                 (SELECT COALESCE(SUM(file_count), 0) FROM scan_records WHERE status='completed') as total_files_scanned,
                 (SELECT COALESCE(SUM(analyzed_count), 0) FROM scan_records WHERE status='completed') as total_files_analyzed,
                 (SELECT COALESCE(SUM(cleaned_count), 0) FROM scan_records)
                   + (SELECT COALESCE(SUM(cleaned_count), 0) FROM clean_records) as total_files_cleaned,
                 (SELECT COALESCE(SUM(bytes_freed), 0) FROM scan_records)
                   + (SELECT COALESCE(SUM(bytes_freed), 0) FROM clean_records) as total_bytes_freed"""
        ).fetchone()
        return dict(row) if row else {}
