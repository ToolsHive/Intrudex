import os
import json
from datetime import datetime
from flask import Flask
from dotenv import load_dotenv
from flask_migrate import Migrate

from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.errors import errors_bp
from app.routes.logs import logs_bp
from app.routes.view import view_bp
from app.routes.sigma import sigma_bp
from app.routes.sigmarules import sigmarules_bp
from app.routes.sigmarules_api import api_bp as sigmarules_api_bp

from app.models.auth import db
from app.models.logs import db

from init_db import create_admin


def safe_json_filter(obj, indent=None):
    """Custom JSON filter that handles problematic objects safely"""
    def make_safe(item):
        if item is None:
            return None
        elif isinstance(item, (str, int, float, bool)):
            return item
        elif isinstance(item, datetime):
            return item.isoformat()
        elif isinstance(item, (list, tuple)):
            return [make_safe(x) for x in item]
        elif isinstance(item, dict):
            return {str(k): make_safe(v) for k, v in item.items()}
        else:
            return str(item)
    
    try:
        safe_obj = make_safe(obj)
        if indent:
            return json.dumps(safe_obj, indent=indent, ensure_ascii=False)
        else:
            return json.dumps(safe_obj, ensure_ascii=False)
    except Exception as e:
        # Fallback for any remaining issues
        return json.dumps({"error": f"Serialization failed: {str(e)}"})


def create_app():
    app = Flask(__name__)
    load_dotenv()

    app.secret_key = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'

    db.init_app(app)
    migrate = Migrate(app, db)
    app.cli.add_command(create_admin)

    # Register custom JSON filter
    app.jinja_env.filters['safe_tojson'] = safe_json_filter

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(errors_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(view_bp)
    app.register_blueprint(sigma_bp)
    app.register_blueprint(sigmarules_bp)
    app.register_blueprint(sigmarules_api_bp)
    return app