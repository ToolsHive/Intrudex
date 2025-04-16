import os
from flask import Flask
from dotenv import load_dotenv

from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.errors import errors_bp

from app.models.auth import db



def create_app():
    app = Flask(__name__)
    load_dotenv()

    app.secret_key = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'

    db.init_app(app)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(errors_bp)
    return app