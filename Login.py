import os
import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests

from Forms import RegisterForm,LoginForm,UpdateProfileForm,ChangePassword
from flask import Flask, render_template, request, redirect, url_for, session,flash,abort
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt   #buy the blender
bcrypt = Bcrypt()   #initializing the blender
import cryptography
from cryptography.fernet import Fernet
from functools import wraps


import re
app = Flask(__name__)
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
#DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
#Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
# Intialize MySQL
mysql = MySQL(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
google_client_id="494648185587-331iamoak392u2o7bl1h2ornokj4qmse.apps.googleusercontent.com"
client_secrets_file=os.path.join(pathlib.Path(__file__).parent,"client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'loggedin' in session:
            return f(*args,**kwargs)
        else:
            flash('You need to login first')
            return redirect(url_for('login'))
    return wrap


@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=google_client_id
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")

    session['loggedin'] = True



    return redirect('/MyWebApp/home')


@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    login_form=LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        username=login_form.username.data
        password=login_form.password.data
        print(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
        # Fetch one record and return result
        account = cursor.fetchone() #if account dont exist in db, return 0
        if account:
            user_hashpwd = account['password']
            if account and bcrypt.check_password_hash(user_hashpwd, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                # convert encrypted email address to bytes
                encrypted_email = account['email'].encode()

                key_file_name = f"{username}_symmetric.key"
                if not os.path.exists(key_file_name):
                    return "Symmetric key file not found."

                # Open and read the symmetric key file
                file = open(key_file_name, 'rb')
                key = file.read()
                file.close()
                # Load he Symmetric key
                f = Fernet(key)

                # Decrypt the Encrypted Email address
                decrypted_email = f.decrypt(encrypted_email)
                email = decrypted_email.decode()

                if account['role']=='admin':
                    return redirect(url_for('admin_home'))
                else:
                    flash('You successfully log in ')
                    return redirect(url_for('home'))

            else:
                msg = 'Incorrect username/password!'
        else:
            msg = 'Incorrect username/password!'

    return render_template('login.html', msg=msg,form=login_form)


@app.route('/logout')
@login_required
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

    return redirect(url_for('login'))

@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    msg = ''
    register_form=RegisterForm(request.form)
    if request.method == 'POST' and register_form.validate():
        username=register_form.username.data
        password=register_form.password.data
        email=register_form.email.data
        role='customer'
        hashpwd = bcrypt.generate_password_hash(password)

        key = Fernet.generate_key()
        # Write Symmetric key to file – wb:write and close file
        key_file_name = f"{username}_symmetric.key"
        with open(key_file_name, "wb") as fo:
            fo.write(key)
        # Initialize Fernet Class
        f = Fernet(key)

        # convert email address to bytes before saving to Database
        email = email.encode()
        # Encrypt email address
        encrypted_email = f.encrypt(email)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (role,username, hashpwd, encrypted_email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'

    return render_template('register.html', msg=msg,form=register_form)

@app.route('/MyWebApp/home')
@login_required
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))
@app.route('/MyWebApp/admin/home')
def admin_home():
    if 'loggedin' in session:
        return render_template('admin_home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/MyWebApp/profile',methods=['GET','POST'])
@login_required
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        encrypted_email = account['email'].encode()
        username = account['username']
        key_file_name = f"{username}_symmetric.key"

        if not os.path.exists(key_file_name):
            return "Symmetric key file not found."
        with open(key_file_name, 'rb') as key_file:
            key = key_file.read()

        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email)
        email=decrypted_email.decode()

        # Mask the email address
        email_parts = email.split('@')
        masked_email = f"{email_parts[0][0]}***{email_parts[0][-1]}@{email_parts[1]}"

        account['email']=masked_email
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/MyWebApp/admin/profile',methods=['GET','POST'])
def admin_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        encrypted_email = account['email'].encode()
        username = account['username']
        key_file_name = f"{username}_symmetric.key"

        if not os.path.exists(key_file_name):
            return "Symmetric key file not found."
        with open(key_file_name, 'rb') as key_file:
            key = key_file.read()

        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email)
        email = decrypted_email.decode()

        # Mask the email address
        email_parts = email.split('@')
        masked_email = f"{email_parts[0][0]}***{email_parts[0][-1]}@{email_parts[1]}"

        account['email'] = masked_email

        return render_template('admin_profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/MyWebApp/profile/update',methods=['GET','POST'])
@login_required
def update_profile():
    if 'loggedin' in session:
        msg=' '
        update_profile_form=UpdateProfileForm(request.form)
        if request.method=='POST' and update_profile_form.validate():
            new_username=update_profile_form.username.data
            email=update_profile_form.email.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            old_username=account['username']

            old_key_file_name = f"{old_username}_symmetric.key"
            if not os.path.exists(old_key_file_name):
                return "Symmetric key file not found."

            new_key_file_name=f"{new_username}_symmetric.key"
            try:
                os.rename(old_key_file_name, new_key_file_name)
            except Exception as e:
                return f"Error renaming key file: {str(e)}"

            # Open and read the symmetric key file
            with open(new_key_file_name, 'rb') as key_file:
                key = key_file.read()

            f = Fernet(key)

            # convert email address to bytes before saving to Database
            email = email.encode()
            # Encrypt email address
            encrypted_email = f.encrypt(email)

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET username = %s,email=%s WHERE id = %s', (new_username,encrypted_email, session['id']))
            mysql.connection.commit()
            msg = 'You have successfully update!'

            if account['role'] == 'admin':
                return redirect(url_for('admin_profile'))
            else:
                return redirect(url_for('profile'))

        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            id=session['id']
            cursor.execute('SELECT * FROM accounts WHERE id = %s ', (id,))
            account=cursor.fetchone()

            encrypted_email = account['email'].encode()
            username = account['username']
            key_file_name = f"{username}_symmetric.key"

            if not os.path.exists(key_file_name):
                return "Symmetric key file not found."

            # Open and read the symmetric key file
            with open(key_file_name, 'rb') as key_file:
                key = key_file.read()

            f = Fernet(key)
            decrypted_email = f.decrypt(encrypted_email)
            # account['email'] = decrypted_email.decode()
            email = decrypted_email.decode()


            update_profile_form.username.data=account['username']
            update_profile_form.email.data=email
            return render_template('update_profile.html',msg=msg,form=update_profile_form,account=account)
    return redirect(url_for('login'))

@app.route('/MyWebApp/Profile/ChangePassowrd',methods=['GET','POST'])
@login_required
def change_password():
    if 'loggedin' in session:
        msg=' '
        pwd_form=ChangePassword(request.form)
        if request.method=='POST' and pwd_form.validate():
            newpwd=pwd_form.newpwd.data
            confirm_password=pwd_form.confirmpwd.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()

            if newpwd==confirm_password:
                hashpwd = bcrypt.generate_password_hash(confirm_password)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE accounts SET password = %s WHERE id = %s', (hashpwd, session['id']))
                mysql.connection.commit()
                msg = 'You have successfully update!'

                if account['role'] == 'admin':
                    return redirect(url_for('admin_profile'))
                else:
                    return redirect(url_for('profile'))
            else:
                msg='Password didnt match.Pls try again'
        return render_template('change_pwd.html',form=pwd_form,msg=msg)
    return redirect(url_for('login'))
#ellexys,email verification
@app.route('/ForgotPassword',methods=['GET','POST'])
@login_required
def forgot_password():
    pass







if __name__== '__main__':
    app.run()