
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path
import sqlite3
import re
import os

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "RIPPLEFIX_SECRET_KEY",
    "local-only-change-this-secret-before-deployment"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "ripplefix.db"

CORS(
    app,
    origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    supports_credentials=True
)


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with get_db_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'citizen'
                    CHECK(role IN ('citizen', 'admin'))
            )
        """)

        columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "username" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN username TEXT"
            )

        db.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username
            ON users(username)
            WHERE username IS NOT NULL
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_code TEXT UNIQUE,
                title TEXT NOT NULL,
                issue_type TEXT NOT NULL,
                location TEXT,
                location_name TEXT,
                latitude REAL,
                longitude REAL,
                severity INTEGER NOT NULL,
                frequency INTEGER NOT NULL,
                affected INTEGER NOT NULL,
                description TEXT,
                reported_by INTEGER NOT NULL,
                citizen_phone TEXT,
                status TEXT NOT NULL DEFAULT 'Reported',
                priority_score INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reported_by) REFERENCES users(id)
            )
        """)


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "message": "RippleFix backend is running!",
        "database": "SQLite",
        "status": "OK"
    })


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not name or len(name) > 100:
        return jsonify({
            "error": "Enter a valid full name."
        }), 400

    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
        return jsonify({
            "error": (
                "Username must be 3-30 characters, "
                "using letters, numbers or underscores."
            )
        }), 400

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({
            "error": "Enter a valid email address."
        }), 400

    if not isinstance(password, str) or len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters."
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with get_db_connection() as db:
            cursor = db.execute("""
                INSERT INTO users
                    (name, username, email, password_hash, role)
                VALUES (?, ?, ?, ?, 'citizen')
            """, (name, username, email, password_hash))

            user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "That username or email is already registered."
        }), 409

    return jsonify({
        "message": "Registration successful. Please log in.",
        "user": {
            "id": user_id,
            "name": name,
            "username": username,
            "email": email,
            "role": "citizen"
        }
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    identifier = str(data.get("identifier", "")).strip()
    password = data.get("password", "")

    if not identifier or not isinstance(password, str) or not password:
        return jsonify({
            "error": "Enter your username/email and password."
        }), 400

    with get_db_connection() as db:
        user = db.execute("""
            SELECT id, name, username, email, password_hash, role
            FROM users
            WHERE lower(email) = lower(?)
               OR lower(username) = lower(?)
        """, (identifier, identifier)).fetchone()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "error": "Invalid username/email or password."
        }), 401

    session.clear()
    session["user_id"] = user["id"]

    return jsonify({
        "message": "Login successful!",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200


@app.route("/api/issues", methods=["POST"])
def create_issue():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Please log in before reporting an issue."
        }), 401

    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    issue_type = str(data.get("type", "")).strip()
    location = str(data.get("location", "")).strip()
    location_name = str(data.get("locationName", "")).strip()
    description = str(data.get("description", "")).strip()
    citizen_phone = str(data.get("citizenPhone", "")).strip()

    try:
        latitude = float(data.get("latitude"))
        longitude = float(data.get("longitude"))
        severity = int(data.get("severity"))
        frequency = int(data.get("frequency"))
        affected = int(data.get("affected"))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Please provide valid coordinates and report values."
        }), 400

    if not title or not issue_type or not location or not description:
        return jsonify({
            "error": "Please complete all required report fields."
        }), 400

    if not 1 <= severity <= 4 or not 1 <= frequency <= 4:
        return jsonify({
            "error": "Severity and frequency must be between 1 and 4."
        }), 400

    if affected < 1:
        return jsonify({
            "error": "People affected must be at least 1."
        }), 400

    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return jsonify({
            "error": "The selected map coordinates are invalid."
        }), 400

    if not re.fullmatch(r"[0-9]{10}", citizen_phone):
        return jsonify({
            "error": "Enter a valid 10-digit phone number."
        }), 400

    priority_score = severity * frequency * affected

    with get_db_connection() as db:
        # Confirm that the session belongs to an existing user.
        user = db.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if user is None:
            session.clear()
            return jsonify({
                "error": "Your session is no longer valid. Please log in again."
            }), 401

        cursor = db.execute("""
            INSERT INTO issues (
                issue_code, title, issue_type, location, location_name,
                latitude, longitude, severity, frequency, affected,
                description, reported_by, citizen_phone, status,
                priority_score
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Reported', ?
            )
        """, (
            f"RF-{__import__('time').time_ns()}",
            title, issue_type, location, location_name,
            latitude, longitude, severity, frequency, affected,
            description, user_id, citizen_phone, priority_score
        ))

        issue_id = cursor.lastrowid

        saved_issue = db.execute(
            "SELECT issue_code FROM issues WHERE id = ?",
            (issue_id,)
        ).fetchone()

    return jsonify({
        "message": "Issue reported successfully!",
        "issue": {
            "id": issue_id,
            "issueCode": saved_issue["issue_code"],
            "title": title,
            "type": issue_type,
            "location": location,
            "locationName": location_name,
            "latitude": latitude,
            "longitude": longitude,
            "severity": severity,
            "frequency": frequency,
            "affected": affected,
            "description": description,
            "citizenPhone": citizen_phone,
            "status": "Reported",
            "score": priority_score
        }
    }), 201

@app.route("/api/issues", methods=["GET"])
def get_issues():
    with get_db_connection() as db:
        rows = db.execute("""
            SELECT
                issues.id,
                issues.issue_code,
                issues.title,
                issues.issue_type,
                issues.location,
                issues.location_name,
                issues.latitude,
                issues.longitude,
                issues.severity,
                issues.frequency,
                issues.affected,
                issues.description,
                issues.citizen_phone,
                issues.status,
                issues.priority_score,
                issues.created_at,
                users.name AS reported_by
            FROM issues
            LEFT JOIN users ON issues.reported_by = users.id
            ORDER BY issues.priority_score DESC, issues.id DESC
        """).fetchall()

    issues = []

    for row in rows:
        issues.append({
            "id": row["id"],
            "issueCode": row["issue_code"],
            "title": row["title"],
            "type": row["issue_type"],
            "location": row["location"],
            "locationName": row["location_name"],
            "latitude": row["latitude"],
            "longitude": row["longitude"],
            "severity": row["severity"],
            "frequency": row["frequency"],
            "affected": row["affected"],
            "description": row["description"],
            "citizenPhone": row["citizen_phone"],
            "status": row["status"],
            "score": row["priority_score"],
            "date": row["created_at"],
            "reportedBy": row["reported_by"] or "Citizen"
        })

    return jsonify({
        "count": len(issues),
        "issues": issues
    }), 200

# =====================================================
# ADMIN: UPDATE ISSUE STATUS
# =====================================================

@app.route("/api/issues/<int:issue_id>/status", methods=["PATCH"])
def update_issue_status_api(issue_id):
    data = request.get_json(silent=True) or {}
    new_status = str(data.get("status", "")).strip()

    allowed_statuses = ["Reported", "In Progress", "Resolved"]

    if new_status not in allowed_statuses:
        return jsonify({"error": "Invalid issue status."}), 400

    # Require a logged-in administrator.
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Please log in to the admin account."}), 401

    with get_db_connection() as db:
        user = db.execute(
            "SELECT role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        if not user:
            session.clear()
            return jsonify({
                "error": "Session user not found. Please log in again."
            }), 401
        if user["role"] != "admin":
            return jsonify({
                "error": "Administrator access required."
            }), 403

        result = db.execute(
            "UPDATE issues SET status = ? WHERE id = ?",
            (new_status, issue_id)
        )

        if result.rowcount == 0:
            return jsonify({"error": "Issue not found."}), 404

    return jsonify({
        "message": "Issue status updated successfully.",
        "id": issue_id,
        "status": new_status
    }), 200


# =====================================================
# ADMIN: CHECK CURRENT SESSION
# =====================================================

@app.route("/api/session", methods=["GET"])
def check_session():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"loggedIn": False}), 401

    with get_db_connection() as db:
        user = db.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if not user:
        session.clear()
        return jsonify({"loggedIn": False}), 401

    return jsonify({
        "loggedIn": True,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200

initialize_database()


if __name__ == "__main__":
    app.run(debug=True)
