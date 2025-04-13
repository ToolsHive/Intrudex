from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models.auth import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user'] = user.username
            return redirect(url_for('main.index'))
        else:
            flash('Invalid credentials', 'error')

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('auth.login'))
