import click
from flask import current_app
from app.models.auth import db, User
import getpass

@click.command("create-admin")
def create_admin():
    """Create an admin user interactively."""
    with current_app.app_context():
        username = input("Enter admin username: ")
        if User.query.filter_by(username=username).first():
            print(f"⚠️ User '{username}' already exists.")
            return

        password = getpass.getpass("Enter admin password: ")
        confirm_password = getpass.getpass("Confirm admin password: ")

        if password != confirm_password:
            print("❌ Passwords do not match. Aborting.")
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"✅ Admin user '{username}' created successfully!")
