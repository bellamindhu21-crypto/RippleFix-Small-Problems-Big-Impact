
from app import get_db_connection
from werkzeug.security import generate_password_hash

username = "admin"
email = "admin@ripplefix.local"
password = "admin123"

with get_db_connection() as db:
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (username, email)
    ).fetchone()

    if existing:
        db.execute(
            """UPDATE users
               SET name = ?, username = ?, email = ?,
                   password_hash = ?, role = ?
               WHERE id = ?""",
            (
                "RippleFix Admin",
                username,
                email,
                generate_password_hash(password),
                "admin",
                existing["id"]
            )
        )
    else:
        db.execute(
            """INSERT INTO users
               (name, username, email, password_hash, role)
               VALUES (?, ?, ?, ?, ?)""",
            (
                "RippleFix Admin",
                username,
                email,
                generate_password_hash(password),
                "admin"
            )
        )

print("Admin account created successfully.")
print("Username: admin")
print("Password: admin123")
