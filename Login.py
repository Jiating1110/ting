

from Forms import RegisterForm,LoginForm,UpdateProfileForm,ChangePassword
from flask import Flask, render_template, request, redirect, url_for, session,flash
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

def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'loggedin' in session:
            return f(*args,**kwargs)
        else:
            flash('You need to login first')
            return redirect(url_for('login'))
    return wrap



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
                print(session['id'])

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


        # key = Fernet.generate_key()
        # with open("symmetric.key", "wb") as fo:
        #     fo.write(key)
        #
        # f = Fernet(key)
        #
        # email = email.encode()
        # encrypted_email = f.encrypt(email)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (role,username, hashpwd, email,))
        mysql.connection.commit()
        msg = 'You have successfully registered!'

    return render_template('register.html', msg=msg,form=register_form)

@app.route('/MyWebApp/home')
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
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

            #
            # encrypted_email=account['email'].encode()
            # file = open('symmetric.key', 'rb')
            # key = file.read()
            # file.close()
            # f=Fernet(key)
            # decrypted_email=f.decrypt(encrypted_email)
            # account['email']=decrypted_email.decode()


        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
@app.route('/MyWebApp/admin/profile',methods=['GET','POST'])
def admin_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        return render_template('admin_profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/MyWebApp/profile/update',methods=['GET','POST'])
def update_profile():
    if 'loggedin' in session:
        msg=' '
        update_profile_form=UpdateProfileForm(request.form)
        if request.method=='POST' and update_profile_form.validate():
            username=update_profile_form.username.data
            email=update_profile_form.email.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET username = %s,email=%s WHERE id = %s', (username,email, session['id']))
            mysql.connection.commit()
            print('update profile',session['id'])
            msg='You have successfully update!'
            return redirect(url_for('profile'))
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            username=session['username']
            cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
            account=cursor.fetchone()

            update_profile_form.username.data=account['username']
            update_profile_form.email.data=account['email']
            return render_template('update_profile.html',msg=msg,form=update_profile_form,account=account)
    return redirect(url_for('login'))

@app.route('/MyWebApp/Profile/ChangePassowrd',methods=['GET','POST'])
def change_password():
    if 'loggedin' in session:
        msg=' '
        pwd_form=ChangePassword(request.form)
        if request.method=='POST' and pwd_form.validate():
            newpwd=pwd_form.newpwd.data
            confirm_password=pwd_form.confirmpwd.data

            if newpwd==confirm_password:
                hashpwd = bcrypt.generate_password_hash(confirm_password)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE accounts SET password = %s WHERE id = %s', (hashpwd, session['id']))
                mysql.connection.commit()
                msg = 'You have successfully update!'

                return redirect(url_for('profile'))
            else:
                msg='Password didnt match.Pls try again'
        return render_template('change_pwd.html',form=pwd_form,msg=msg)
    return redirect(url_for('login'))










if __name__== '__main__':
    app.run()