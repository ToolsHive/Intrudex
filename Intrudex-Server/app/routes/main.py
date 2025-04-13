from flask import Blueprint, render_template, session, redirect, url_for

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('auth.login'))  # 🚫 Redirect if not logged in
    return render_template('index.html')
