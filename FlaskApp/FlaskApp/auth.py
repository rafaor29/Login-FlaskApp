# auth.py

from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from .models import User
from . import db
import jwt
import datetime
from functools import wraps

auth = Blueprint('auth', __name__)
SECRET_KEY = 'bcd63c31fc0fe553196db181187ee286d8896796f0ad4088'

#Decorator que comprueba si el token es valido
def pedir_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')

        if not token: 
            return jsonify({'message': 'No se encuentra el token'}), 401
        try: 
            data = jwt.decode(token, SECRET_KEY)
            current_user = User.query.filter_by(email=data['user']).first()
        except:
            #si el token ha expirado redirige al login
            current_user = None
            logout_user()
            return redirect(url_for('main.index'))

        return f(current_user, *args, **kwargs)

    return decorated

@auth.route('/profile/<name>')
@pedir_token
def protegido(current_user, name):
    data = request.get_json()
    user = User.query.filter_by(name=name).first()
    if not user:
        return redirect(url_for('main.index'))

    return render_template('profile.html', nombre=user.name)

@auth.route('/login')
def login():
    
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # comprobamos que el usuario existe y que la pw se corresponde    
    if not user or not user.password == password: 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # el usuario tiene los credenciales, se le da acceso.
    login_user(user, remember=remember)
    token = jwt.encode({'user': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=7)}, SECRET_KEY)

    #devolvemos el token de autenticacion en una cookie httponly
    resp = make_response(redirect(url_for('main.profile')))
    resp.set_cookie('token', token, httponly=True)
    return resp 

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() 

    if user: # if a user is found, we want to redirect back to signup page so user can try again  
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, password=password)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))