"""Administrative CLI script to provision development and initial operator accounts (Phase 9).

Credentials must be supplied securely via environment variables or interactive prompts.
No default passwords are stored in source code.

Environment Variables:
    NIDS_ADMIN_USERNAME    (default: 'admin')
    NIDS_ADMIN_PASSWORD
    NIDS_ANALYST_USERNAME  (default: 'analyst')
    NIDS_ANALYST_PASSWORD
    NIDS_VIEWER_USERNAME   (default: 'viewer')
    NIDS_VIEWER_PASSWORD

Usage:
    # Single operator creation:
    python -m backend.scripts.create_admin --username admin --role ADMIN

    # Seed all development roles from environment variables:
    python -m backend.scripts.create_admin --seed-all-dev-users
"""

import argparse
import getpass
import os
import sys
from backend.app.core.security import get_password_hash
from backend.app.db.session import Base, SessionLocal, engine
from backend.app.models.user import UserRecord
from backend.app.repositories.user_repository import UserRepository


def get_secure_password(env_var_name: str, prompt_label: str, cli_arg: str = None) -> str:
    """Retrieve password from CLI argument, environment variable, or secure interactive prompt."""
    if cli_arg:
        return cli_arg

    env_val = os.getenv(env_var_name)
    if env_val:
        return env_val

    if sys.stdin.isatty():
        pw = getpass.getpass(f"Enter password for {prompt_label}: ")
        if pw:
            return pw

    print(
        f"[ERROR] Missing required password for {prompt_label}.\n"
        f"Please supply the password by setting the environment variable '{env_var_name}',\n"
        f"passing '--password <password>', or running in an interactive terminal.",
        file=sys.stderr,
    )
    sys.exit(1)


def provision_user(db, username: str, password: str, role: str = "ADMIN") -> UserRecord:
    """Safely provision a user account with hashed password if not already present.
    
    Idempotent: If the user already exists, it is NOT overwritten or reset.
    """
    norm_username = username.strip()
    norm_role = role.upper().strip()

    existing = UserRepository.get_by_username(db, norm_username)
    if existing:
        print(f"[INFO] User '{norm_username}' already exists. Skipping (passwords will not be overwritten).")
        return existing

    new_user = UserRecord(
        username=norm_username,
        password_hash=get_password_hash(password),
        role=norm_role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    print(f"[SUCCESS] Created operator account '{norm_username}' (Role: {norm_role}, ID: {new_user.id}).")
    return new_user


def main():
    parser = argparse.ArgumentParser(description="Provision NIDS initial operators and dev accounts.")
    parser.add_argument(
        "--username",
        default=os.getenv("NIDS_ADMIN_USERNAME", "admin"),
        help="Username to create (defaults to NIDS_ADMIN_USERNAME or 'admin')",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password for user (recommended: supply via environment variable or interactive prompt)",
    )
    parser.add_argument(
        "--role",
        default="ADMIN",
        choices=["ADMIN", "ANALYST", "VIEWER"],
        help="RBAC role (ADMIN, ANALYST, VIEWER)",
    )
    parser.add_argument(
        "--seed-all-dev-users",
        action="store_true",
        help="Seed initial ADMIN, ANALYST, and VIEWER accounts using environment variables",
    )

    args = parser.parse_args()

    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if args.seed_all_dev_users:
            print("--- Provisioning Development Operators (Idempotent) ---")
            
            # 1. Admin Operator
            admin_user = os.getenv("NIDS_ADMIN_USERNAME", "admin")
            if not UserRepository.get_by_username(db, admin_user):
                admin_pw = get_secure_password("NIDS_ADMIN_PASSWORD", f"Admin user '{admin_user}'")
                provision_user(db, admin_user, admin_pw, "ADMIN")
            else:
                print(f"[INFO] User '{admin_user}' already exists. Skipping.")

            # 2. Analyst Operator
            analyst_user = os.getenv("NIDS_ANALYST_USERNAME", "analyst")
            if not UserRepository.get_by_username(db, analyst_user):
                analyst_pw = get_secure_password("NIDS_ANALYST_PASSWORD", f"Analyst user '{analyst_user}'")
                provision_user(db, analyst_user, analyst_pw, "ANALYST")
            else:
                print(f"[INFO] User '{analyst_user}' already exists. Skipping.")

            # 3. Viewer Operator
            viewer_user = os.getenv("NIDS_VIEWER_USERNAME", "viewer")
            if not UserRepository.get_by_username(db, viewer_user):
                viewer_pw = get_secure_password("NIDS_VIEWER_PASSWORD", f"Viewer user '{viewer_user}'")
                provision_user(db, viewer_user, viewer_pw, "VIEWER")
            else:
                print(f"[INFO] User '{viewer_user}' already exists. Skipping.")
        else:
            existing = UserRepository.get_by_username(db, args.username)
            if existing:
                print(f"[INFO] User '{args.username}' already exists. Skipping.")
            else:
                pw = get_secure_password(f"NIDS_{args.role}_PASSWORD", f"User '{args.username}'", args.password)
                provision_user(db, args.username, pw, args.role)
    finally:
        db.close()


if __name__ == "__main__":
    main()
