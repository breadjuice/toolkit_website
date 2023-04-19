from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, make_response
from flask_wtf import FlaskForm
from flask_login import login_required, LoginManager
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
import os
import logging
import subprocess
app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = '6m4LDKF1fJhC367aqRrU'

app.logger.setLevel(logging.INFO)
handler = logging.FileHandler('app.log')
app.logger.addHandler(handler)

class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    submit = SubmitField('Log In')

@app.route('/')
def home():
    # action = request.form['action']
    # if action == 'process':
    #     redirect(url_for('login'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # lookup the user details in the user_info directory
        user_info_file = os.path.join('user_info', username + '.txt')
        if os.path.exists(user_info_file):
            with open(user_info_file, 'r') as f:
                hashed_password = f.read().strip()
                if check_password_hash(hashed_password, password):
                    # start the user session and redirect to upload page
                    session['username'] = username
                    return redirect(url_for('upload'))
        # show an error message if username or password is invalid
        flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    global file
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join(UPLOAD_FOLDER, secure_filename(file.filename)))
        return redirect(url_for('download'))
    return render_template('upload.html')

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(app.config['OUTPUT_DIR'], filename)
    if not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as f:
        contents = f.read()
    response = make_response(contents)
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    return response

if __name__ == '__main__':
    app.run(port=8000,debug=True)