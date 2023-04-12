from flask_app import app
from flask import render_template,redirect,session,request,flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    if 'logged_in' in session:
        if session['logged_in'] == True:
            data = {'id': session['user_id']}
            user = User.user_logged_in(data)
            print(session['user_id'])
            return render_template('dashboard.html', user=user)
        else:
            return render_template('index.html')
    else:
        return render_template('index.html')

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    if request.form['password'] != request.form['confirm_password']:
        flash('Passwords did not match', 'register')
        return redirect('/')
    if not User.user_vald_register(request.form):
        return redirect('/')
    if User.unique_email(request.form['email']) == True:
        return redirect('/')
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': pw_hash
    }
    user_id = User.register_user(data)
    session['user_id'] = user_id
    session['logged_in'] = True
    return redirect('/register/success')

@app.route('/register/success')
def register_success():
    if session['logged_in'] == False:
        return redirect('/')
    data = {'id': session['user_id']}
    user = User.user_logged_in(data)
    return render_template('dashboard.html', user=user)

@app.route('/login', methods=['POST'])
def login():
    data = { 'email': request.form['email'] }
    user_in_db = User.get_by_email(data)
    if not user_in_db:
        flash('Invalid Email/Password', 'login')
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash('Invalid Email/Password', 'login')
        return redirect('/')
    session['user_id'] = user_in_db.id
    session['logged_in'] = True
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    data = {'id': session['user_id']}
    user = User.user_logged_in(data)
    return render_template('dashboard.html', user=user)