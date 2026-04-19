import json
import sqlite3
from typing import Optional
from src.config import DB_PATH, JSONL_PATH


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            date TEXT NOT NULL,
            cve_id TEXT DEFAULT '',
            repo TEXT NOT NULL,
            language TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL DEFAULT 0.0,
            package_name TEXT DEFAULT '',
            pattern_id TEXT NOT NULL,
            vuln_type TEXT DEFAULT '',
            root_cause TEXT DEFAULT '',
            impact TEXT DEFAULT '',
            fix_summary TEXT DEFAULT '',
            key_diff TEXT DEFAULT '',
            confidence TEXT DEFAULT 'LOW',
            commit_url TEXT DEFAULT '',
            status TEXT DEFAULT 'ANALYZED',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS patterns (
            pattern_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            occurrences INTEGER DEFAULT 1,
            languages TEXT DEFAULT '[]',
            related_advisories TEXT DEFAULT '[]'
        );

        CREATE INDEX IF NOT EXISTS idx_advisories_pattern
            ON advisories(pattern_id);
        CREATE INDEX IF NOT EXISTS idx_advisories_date
            ON advisories(date);
        CREATE INDEX IF NOT EXISTS idx_advisories_status
            ON advisories(status);
    """)

    conn.commit()
    conn.close()


def rebuild_from_jsonl():
    init_db()

    if not JSONL_PATH.exists() or JSONL_PATH.stat().st_size == 0:
        return

    conn = sqlite3.connect(str(DB_PATH))

    with open(JSONL_PATH, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(f"  WARNING: skipping malformed JSONL at line {lineno}")
                continue
            record_type = record.get("_type")

            if record_type == "advisory":
                _upsert_advisory(conn, record)
            elif record_type == "pattern":
                _upsert_pattern(conn, record)

    conn.commit()
    conn.close()


def advisory_exists(ghsa_id: str) -> bool:
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "SELECT 1 FROM advisories WHERE id = ?", (ghsa_id,)
    )
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def insert_analysis(result: dict) -> dict:
    conn = sqlite3.connect(str(DB_PATH))

    conn.execute("""
        INSERT OR REPLACE INTO advisories
        (id, date, cve_id, repo, language, severity, cvss_score,
         package_name, pattern_id, vuln_type, root_cause, impact,
         fix_summary, key_diff, confidence, commit_url, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ANALYZED')
    """, (
        result["ghsa_id"], result["date"], result["cve_id"],
        result["repo"], result["language"], result["severity"],
        result["cvss_score"], result["package_name"],
        result["pattern_id"], result["vuln_type"],
        result["root_cause"], result["impact"],
        result["fix_summary"], result["key_diff"],
        result["confidence"], result["commit_url"],
    ))

    pattern_match = _update_pattern(conn, result)
    conn.commit()
    conn.close()

    return pattern_match


def insert_pending(ghsa_id: str, advisory: dict):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT OR IGNORE INTO advisories
        (id, date, repo, language, severity, cvss_score,
         package_name, pattern_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING')
    """, (
        ghsa_id,
        advisory.get("published_at", "")[:10],
        advisory.get("repo", ""),
        _ecosystem_to_lang(advisory.get("ecosystem", "")),
        advisory.get("severity", "UNKNOWN"),
        advisory.get("cvss_score", 0.0),
        advisory.get("package_name", ""),
    ))
    conn.commit()
    conn.close()


def get_pending_ids() -> list[str]:
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "SELECT id FROM advisories WHERE status = 'PENDING'"
    )
    ids = [row[0] for row in cursor.fetchall()]
    conn.close()
    return ids


def _update_pattern(conn: sqlite3.Connection, result: dict) -> dict:
    pattern_id = result["pattern_id"]

    cursor = conn.execute(
        "SELECT occurrences, languages, related_advisories FROM patterns WHERE pattern_id = ?",
        (pattern_id,)
    )
    row = cursor.fetchone()

    if row is None:
        conn.execute("""
            INSERT INTO patterns (pattern_id, first_seen, occurrences, languages, related_advisories)
            VALUES (?, ?, 1, ?, ?)
        """, (
            pattern_id,
            result["date"],
            json.dumps([result["language"]]),
            json.dumps([result["ghsa_id"]]),
        ))
        return {
            "is_new": True,
            "occurrences": 1,
            "previous_advisories": [],
            "languages": [result["language"]],
        }

    occurrences = row[0] + 1
    languages = json.loads(row[1])
    related = json.loads(row[2])

    if result["language"] not in languages:
        languages.append(result["language"])
    related.append(result["ghsa_id"])

    conn.execute("""
        UPDATE patterns
        SET occurrences = ?, languages = ?, related_advisories = ?
        WHERE pattern_id = ?
    """, (occurrences, json.dumps(languages), json.dumps(related), pattern_id))

    return {
        "is_new": False,
        "occurrences": occurrences,
        "previous_advisories": related[:-1],
        "languages": languages,
    }


def export_to_jsonl():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    tmp_path = JSONL_PATH.with_suffix(".jsonl.tmp")

    with open(tmp_path, "w") as f:
        for row in conn.execute("SELECT * FROM patterns ORDER BY first_seen"):
            record = dict(row)
            record["_type"] = "pattern"
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        for row in conn.execute("SELECT * FROM advisories ORDER BY date, id"):
            record = dict(row)
            record["_type"] = "advisory"
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    import os
    os.replace(tmp_path, JSONL_PATH)
    conn.close()


def get_advisories_for_date(date: str) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM advisories WHERE date = ? AND status = 'ANALYZED' ORDER BY cvss_score DESC",
        (date,)
    )
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def get_pattern_info(pattern_id: str) -> Optional[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM patterns WHERE pattern_id = ?", (pattern_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        result = dict(row)
        result["languages"] = json.loads(result["languages"])
        result["related_advisories"] = json.loads(result["related_advisories"])
        return result
    return None


def get_recent_dates(n: int = 7) -> list[str]:
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "SELECT DISTINCT date FROM advisories WHERE status = 'ANALYZED' ORDER BY date DESC LIMIT ?",
        (n,)
    )
    dates = [row[0] for row in cursor.fetchall()]
    conn.close()
    return dates


def get_all_advisories() -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM advisories WHERE status = 'ANALYZED' ORDER BY date DESC, cvss_score DESC"
    )
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def get_stats() -> dict:
    conn = sqlite3.connect(str(DB_PATH))
    total_advisories = conn.execute(
        "SELECT COUNT(*) FROM advisories WHERE status = 'ANALYZED'"
    ).fetchone()[0]
    total_patterns = conn.execute(
        "SELECT COUNT(*) FROM patterns"
    ).fetchone()[0]
    pending_count = conn.execute(
        "SELECT COUNT(*) FROM advisories WHERE status = 'PENDING'"
    ).fetchone()[0]
    conn.close()
    return {
        "total_advisories": total_advisories,
        "total_patterns": total_patterns,
        "pending_count": pending_count,
    }


def _upsert_advisory(conn: sqlite3.Connection, record: dict):
    fields = [
        "id", "date", "cve_id", "repo", "language", "severity",
        "cvss_score", "package_name", "pattern_id", "vuln_type",
        "root_cause", "impact", "fix_summary", "key_diff",
        "confidence", "commit_url", "status",
    ]
    values = [record.get(f, "") for f in fields]
    placeholders = ", ".join(["?"] * len(fields))
    field_names = ", ".join(fields)
    conn.execute(
        f"INSERT OR REPLACE INTO advisories ({field_names}) VALUES ({placeholders})",
        values,
    )


def _upsert_pattern(conn: sqlite3.Connection, record: dict):
    conn.execute("""
        INSERT OR REPLACE INTO patterns
        (pattern_id, first_seen, occurrences, languages, related_advisories)
        VALUES (?, ?, ?, ?, ?)
    """, (
        record["pattern_id"],
        record["first_seen"],
        record["occurrences"],
        record["languages"] if isinstance(record["languages"], str) else json.dumps(record["languages"]),
        record["related_advisories"] if isinstance(record["related_advisories"], str) else json.dumps(record["related_advisories"]),
    ))


def _ecosystem_to_lang(ecosystem: str) -> str:
    mapping = {
        "NPM": "JavaScript", "GO": "Go", "PIP": "Python",
        "PYPI": "Python", "MAVEN": "Java", "NUGET": "C#",
        "RUBYGEMS": "Ruby", "CRATES_IO": "Rust", "COMPOSER": "PHP",
    }
    return mapping.get(ecosystem.upper(), ecosystem)
