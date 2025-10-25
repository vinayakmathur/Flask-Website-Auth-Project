from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import logout_user,login_required,current_user,login_user

auth = Blueprint('auth', __name__)

# ---------------- LOGIN ROUTE ----------------
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password1').strip()

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email does not exist.', category='error')
        elif not user.password:
            flash('Password missing for this account.', category='error')
        elif check_password_hash(user.password, password):
            flash('Logged in Successfully!', category='success')
            login_user(user,remember=True)
            return redirect(url_for('views.home'))  # redirect after login
        else:
            flash('Incorrect password, try again.', category='error')

    return render_template("Login.html", boolean=True)

# ---------------- LOGOUT ROUTE ----------------
@auth.route('/logout')
@login_required
def logout():
    logout_user()  # logs out the user if using Flask-Login
    flash('Logged out successfully.', category='success')
    return redirect(url_for('auth.login'))

# ---------------- SIGN-UP ROUTE ----------------
@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        first_name = request.form.get('firstname').strip()
        password1 = request.form.get('password1').strip()
        password2 = request.form.get('password2').strip()

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 3:
            flash('Email must be greater than 4 characters.', category='error')
        elif len(first_name) < 2:
            flash('First Name must be greater than 2 characters.', category='error')
        elif not password1:
            flash('Password cannot be empty.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 7 characters.', category='error')
        else:
            new_user = User(
                email=email,
                first_name=first_name,
                password=generate_password_hash(
                    password1, method='pbkdf2:sha256', salt_length=16
                )
            )
            db.session.add(new_user)
            db.session.commit()# ✅ commit the new user
            login_user(user,remember=True)  
            flash('Account Created!!', category='success')
            return redirect(url_for('views.home'))  # redirect after signup

    return render_template("signup.html")
