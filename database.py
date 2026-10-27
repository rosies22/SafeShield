import sqlite3
from pathlib import Path

DATABASE_FILE = Path(__file__).parent / "safeshield.db"


def get_connection():
    """Create a connection to the SafeShield database."""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create the incidents table if it does not already exist."""
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                location TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Unverified',
                created_at TEXT NOT NULL
            )
        """)


def create_incident(incident_type, location, description, created_at):
    """Save a new incident and return its database ID."""
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO incidents (
                type, location, description, status, created_at
            )
            VALUES (?, ?, ?, 'Unverified', ?)
        """, (incident_type, location, description, created_at))

        return cursor.lastrowid


def get_all_incidents():
    """Retrieve incidents, newest first."""
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, type, location, description, status, created_at
            FROM incidents
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]


def update_incident_status(incident_id, new_status):
    """Update an incident's status if the ID and status are valid."""
    allowed_statuses = {
        "Under Review",
        "Verified",
        "Rejected",
        "Resolved",
    }

    if new_status not in allowed_statuses:
        return False

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE incidents
            SET status = ?
            WHERE id = ?
            """,
            (new_status, incident_id),
        )

        return cursor.rowcount > 0

