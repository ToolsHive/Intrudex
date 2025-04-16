from flask import Blueprint, render_template

errors_bp = Blueprint('errors', __name__)

@errors_bp.app_errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@errors_bp.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@errors_bp.app_errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500