import os
from flask import Flask
from dotenv import load_dotenv
from flask_migrate import Migrate

from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.errors import errors_bp
from app.routes.logs import logs_bp
from app.routes.view import view_bp

from app.models.auth import db
from app.models.logs import db

from init_db import create_admin


def create_app():
    app = Flask(__name__)
    load_dotenv()

    app.secret_key = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'

    db.init_app(app)
    migrate = Migrate(app, db)
    app.cli.add_command(create_admin)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(view_bp)
    return app