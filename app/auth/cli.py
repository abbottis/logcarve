"""Local credential administration (T5).

Creates the first admin user and issues scoped machine tokens. Secrets
always come from the environment, never from command arguments, logs or
version control. Newly issued token plaintext is printed once and never
stored.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from app.auth.passwords import hash_password
from app.auth.tokens import create_admin_user, issue_token
from app.db.database import writer_transaction
from app.db.migrations_runner import migrate


def _env_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise SystemExit(f"error: {name} environment variable must be set")
    return value


def cmd_create_admin(args: argparse.Namespace) -> int:
    migrate(Path(args.db))
    password = _env_secret("LOGCARVE_ADMIN_PASSWORD")
    with writer_transaction(Path(args.db)) as conn:
        user_id = create_admin_user(
            conn, username=args.username, password_hash=hash_password(password)
        )
    print(json.dumps({"user_id": user_id, "username": args.username}))
    return 0


def cmd_issue_token(args: argparse.Namespace) -> int:
    migrate(Path(args.db))
    with writer_transaction(Path(args.db)) as conn:
        if conn.execute("SELECT id FROM sites WHERE id = ?", (args.site_id,)).fetchone() is None:
            print(f"error: unknown site: {args.site_id}", file=sys.stderr)
            return 1
        token_id, plaintext = issue_token(
            conn,
            name=args.name,
            site_id=args.site_id,
            scopes=tuple(args.scopes.split()),
            expires_at=args.expires_at,
        )
    print(json.dumps({"token_id": token_id, "token": plaintext}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logcarve-auth", description="Local credential administration"
    )
    parser.add_argument("--db", required=True, help="SQLite database file")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-admin", help="Create a local admin user (password via env)")
    create.add_argument("--username", required=True)
    create.set_defaults(func=cmd_create_admin)

    issue = sub.add_parser("issue-token", help="Issue a scoped machine token (shown once)")
    issue.add_argument("--name", required=True)
    issue.add_argument("--site-id", required=True)
    issue.add_argument("--scopes", default="analytics:read")
    issue.add_argument(
        "--expires-at", default=None, help="ISO UTC timestamp or empty for no expiry"
    )
    issue.set_defaults(func=cmd_issue_token)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary maps errors to exit 1
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
