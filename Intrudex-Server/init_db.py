# init_db.py
from app import create_app
from app.models.auth import db, User
import getpass

app = create_app()

with app.app_context():
    db.create_all()
    print("✅ Database and tables created!")

    username = input("Enter admin username: ")
    if User.query.filter_by(username=username).first():
        print(f"⚠️ User '{username}' already exists.")
    else:
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
