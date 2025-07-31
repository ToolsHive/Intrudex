import click
from flask import current_app
from app.models.auth import db, User
import getpass

@click.command("create-admin")
@click.option("--username", prompt=False, help="Admin username")
@click.option("--password", prompt=False, hide_input=True, help="Admin password")
def create_admin(username, password):
    """Create an admin user (interactive or via CLI args)."""
    with current_app.app_context():
        # Fallback to interactive prompt if not provided
        if not username:
            username = input("Enter admin username: ")

        if User.query.filter_by(username=username).first():
            print(f"⚠️ User '{username}' already exists.")
            return

        if not password:
            password = getpass.getpass("Enter admin password: ")
            confirm_password = getpass.getpass("Confirm admin password: ")

            if password != confirm_password:
                print("❌ Passwords do not match. Aborting.")
                return

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f"✅ Admin user '{username}' created successfully!")
