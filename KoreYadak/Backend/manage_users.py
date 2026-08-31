import sys
import getpass
import re
import secrets
import hashlib

from Backend.database import get_connection
from Backend.main import hash_password, utc_now, validate_password, validate_username


def list_users():
    connection = get_connection()
    rows = connection.execute("""
        SELECT id, username, must_change_password, created_at, updated_at
        FROM users
        ORDER BY id
    """).fetchall()
    connection.close()

    if not rows:
        print("No users found.")
        return

    print()
    print(f"{'ID':<5}{'Username':<20}{'Must change password':<22}")
    print("-" * 47)

    for row in rows:
        status = "YES" if row["must_change_password"] else "NO"
        print(f"{row['id']:<5}{row['username']:<20}{status:<22}")

    print()


def reset_password(username):
    username = username.strip()

    connection = get_connection()
    user = connection.execute(
        "SELECT id, username FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    connection.close()

    if user is None:
        print(f"User not found: {username}")
        return

    print(f"Reset password for: {user['username']}")

    while True:
        password = getpass.getpass("New password: ")
        repeat = getpass.getpass("Repeat new password: ")

        if password != repeat:
            print("Passwords do not match.")
            continue

        try:
            validate_password(password)
        except ValueError as exc:
            print(exc)
            continue

        break

    connection = get_connection()
    connection.execute("""
        UPDATE users
        SET password_hash = ?,
            must_change_password = 0,
            updated_at = ?
        WHERE id = ?
    """, (
        hash_password(password),
        utc_now(),
        user["id"]
    ))

    # Invalidate existing sessions for this account.
    connection.execute(
        "DELETE FROM sessions WHERE user_id = ?",
        (user["id"],)
    )

    connection.commit()
    connection.close()

    print("Password reset successfully.")
    print("Existing login sessions for this user were logged out.")


def change_username(old_username, new_username):
    try:
        new_username = validate_username(new_username)
    except ValueError as exc:
        print(exc)
        return

    connection = get_connection()

    user = connection.execute(
        "SELECT id, username FROM users WHERE username = ?",
        (old_username.strip(),)
    ).fetchone()

    if user is None:
        connection.close()
        print(f"User not found: {old_username}")
        return

    duplicate = connection.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        (new_username, user["id"])
    ).fetchone()

    if duplicate is not None:
        connection.close()
        print("That username is already in use.")
        return

    connection.execute("""
        UPDATE users
        SET username = ?, updated_at = ?
        WHERE id = ?
    """, (new_username, utc_now(), user["id"]))

    connection.commit()
    connection.close()

    print(f"Username changed: {user['username']} -> {new_username}")


def usage():
    print("""
Kore Yadak User Manager

Commands:

  python -m Backend.manage_users list
      Show all users and account status.

  python -m Backend.manage_users reset USERNAME
      Reset a user's password.

  python -m Backend.manage_users rename OLD_USERNAME NEW_USERNAME
      Change a username.

Examples:

  python -m Backend.manage_users list
  python -m Backend.manage_users reset Erfan
  python -m Backend.manage_users rename Erfan ErfanDev
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        raise SystemExit(1)

    command = sys.argv[1].lower()

    if command == "list":
        list_users()

    elif command == "reset" and len(sys.argv) == 3:
        reset_password(sys.argv[2])

    elif command == "rename" and len(sys.argv) == 4:
        change_username(sys.argv[2], sys.argv[3])

    else:
        usage()
        raise SystemExit(1)
