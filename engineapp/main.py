import logging
import json
import os
import uuid
import pytz

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask import make_response
from google.appengine.ext import deferred
from google.appengine.api import mail
from google.appengine.api import urlfetch
from urllib import urlencode

from google.appengine.datastore.datastore_query import Cursor
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from ndb_files import *
from datetime import *


app = Flask(__name__)
app.secret_key = os.urandom(24)
urlfetch.set_default_fetch_deadline(45)

# google console credientials

CLIENT_ID = '409456169998-t6hi4lba6s6bglpep54p696oa8gca6d9.apps.googleusercontent.com'
CLIENT_SECRET = 'A7nYiIso9mveuh6YIMzUAsZS'
SCOPE = 'https://www.googleapis.com/auth/userinfo.profile email'
REDIRECT_URI = 'http://workwithflask.appspot.com/googlecallback'
USER_PROFILE_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'

""" Google oauth coding stats from here"""


@app.route('/googlelogin')
def index():
    if 'credentials' not in session:
        return redirect(url_for('googlecallback'))
    credentials = json.loads(session['credentials'])
    if credentials['expires_in'] <= 0:
        return redirect(url_for('googlecallback'))
    else:
        headers = {'Authorization': 'Bearer {}'.format(credentials['access_token'])}
        r = urlfetch.fetch(USER_PROFILE_URL, headers=headers, method=urlfetch.GET)
        user = json.loads(r.content)
        session['logged_in'] = True
        session['user_email'] = user.get('email')
        session['username'] = user.get('name')
        mail = user.get('email')
        if UserDetails.query(UserDetails.email_ID == mail).get():
            return redirect(url_for('userpage'))
        UserDetails(userName=user.get("name"), email_ID=user.get("email")).put()
        return redirect(url_for('userpage'))


@app.route('/googlecallback')
def googlecallback():
    if 'code' not in request.args:
        auth_uri = ('https://accounts.google.com/o/oauth2/v2/auth?response_type=code'
                    '&client_id={}&redirect_uri={}&scope={}').format(CLIENT_ID, REDIRECT_URI, SCOPE)

        """Here it will redirect to server for geting authorized code """
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        data = {'code': auth_code,
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'redirect_uri': REDIRECT_URI,
                'grant_type': 'authorization_code'}
        url = 'https://www.googleapis.com/oauth2/v4/token'
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        r = urlfetch.fetch(url, method=urlfetch.POST, payload=urlencode(data), headers=header)

        """ It will replies with access Token"""

        session['credentials'] = r.content
        return redirect(url_for('index'))

"""Google oauth coding ends here"""


def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first')
            return redirect(url_for('homepage'))
    return wrap


def userdetails():
    pwd = request.form['psw']
    user_details = UserDetails(
        userName=request.form['username'],
        email_ID=request.form['email'],
        password=generate_password_hash(pwd)
    )
    user_details.put()


def newbook_request_mailing(to_user, name, book):
    sender = str('saipavan.sankar@adaptavantcloud.com')
    subject_to_user = str("Book Request acknowledgement")
    mailbody_to_user = str('%s Book has been requested successfully. '
                           'Thank you for requesting book on Book Forms.' % book)
    mail.send_mail(sender, to_user, subject_to_user, mailbody_to_user)
    to_admin = sender
    subject_to_admin = str('You have a new Book Request')
    mailbody_to_admin = str('%s from %s has requested for %s book to be added to the list.'
                            ' Please acknowledge and add the book to the '
                            'list' % (name, to_user, book))
    mail.send_mail(sender, to_admin, subject_to_admin, mailbody_to_admin)


def readbook_request_mailing(book, receiver, name):
    sender = str('saipavan.sankar@adaptavantcloud.com')
    subject = str('New Read Book Requested')
    body = str('Your request to read book %s has been submitted successfully.' % book)
    mail.send_mail(sender, receiver, subject, body)
    admin_receiver = sender
    subject_to_admin = str('New Read Book Requested')
    body_to_admin = str('%s from %s has been requested to read %s.' % (name, receiver, book))
    mail.send_mail(sender, admin_receiver, subject_to_admin, body_to_admin)


def admin_request_mail(to):
    sender = str('saipavan.sankar@adaptavantcloud.com')
    subject = str('Make me as a Admin')
    body = str('Click this link and fill up the admin signup form. \nhttp://workwithflask.appspot.com/adminsignup')
    mail.send_mail(sender, to, subject, body)


@app.route('/')
def homepage():
    return render_template('loginpopup.html')


@app.route('/loginpage', methods=['POST'])
def loginpage():
    username = request.form['uname']
    pswd = request.form['psw']
    if UserDetails.query(UserDetails.email_ID == username).get():
        user = UserDetails.query(UserDetails.email_ID == username).get()
        if check_password_hash(user.password, pswd):
            session['logged_in'] = True
            session['user_email'] = username
            session['username'] = user.userName
            return redirect(url_for('userpage'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('homepage'))
    else:
        flash('Invalid user credentials.')
        return redirect(url_for('homepage'))


@app.route('/userpage')
@login_required
def userpage():
    books = Books.query().fetch()
    return render_template('userpage.html', book=books)


@app.route('/userlogout')
def userlogout():
    session.pop('user_email', None)
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('credentials', None)
    return redirect(url_for('homepage'))


@app.route('/bookrequest', methods=['POST'])
def bookrequest():
    book = request.form['requirebook']
    author = request.form['authorname']
    if Books.query(Books.name == book).get():
        if Books.query(Books.author == author).get():
            flash('The Book you requested is already in the Book list.')
            return redirect(url_for('userpage'))
    user_email = session['user_email']
    name = session['username']
    deferred.defer(newbook_request_mailing, user_email, name, book)
    flash('Book requested successfully')
    return redirect(url_for('userpage'))


@app.route('/bookread', methods=['POST'])
def bookread():
    book = request.form['book']
    receiver = session['user_email']
    name = session['username']
    deferred.defer(readbook_request_mailing, book, receiver, name)
    flash('Your book will be sent to you shortly.')
    return redirect(url_for('userpage'))


@app.route('/signup', methods=['POST'])
def signup():
    userdet = UserDetails.query().fetch()
    for user in userdet:
        if user.email_ID == request.form['email']:
            flash('The email ID you entered has already been signed up.')
            return redirect(url_for('homepage'))
        else:
            continue
    else:
        userdetails()
        flash('Signed up successfully. Log in to access your account in BookForm.')
        return redirect(url_for('homepage'))


@app.route('/adminsignup')
def adminsignup():
    return render_template('adminsignup.html')


@app.route('/adminrequest')
def adminrequest():
    to = session['user_email']
    deferred.defer(admin_request_mail, to)
    flash('Check out your email to get the link for admin form.')
    return redirect(url_for('userpage'))


@app.route('/signedup', methods=['POST'])
def signedup():
    if request.form['adminpassword'] == request.form['confirmpassword']:
        if UserDetails.query(UserDetails.email_ID == request.form['adminemail']).get():
            pw = request.form['adminpassword']
            admins = Admins(username=request.form['adminname'],
                            email=request.form['adminemail'],
                            password=generate_password_hash(pw)
                            )
            admins.put()
            flash('Signed up successfully')
            return redirect(url_for('homepage'))
        else:
            flash('You are not a user on BookForms. Only users of BookForms can become Admin on BookForms')
            return redirect(url_for('adminsignup'))
    flash('Passwords do not match')
    return redirect(url_for('adminsignup'))


@app.route('/admin', methods=['POST'])
def admin():
    adminname = request.form['adminname']
    adminpsw = request.form['psw']
    if Admins.query(Admins.email == adminname).get():
        admin = Admins.query(Admins.email == adminname).get()
        if check_password_hash(admin.password, adminpsw):
            session['logged_in'] = True
            return redirect(url_for('adminpage'))
        else:
            flash('Invalid adminname or password.')
            return redirect(url_for('homepage'))
    else:
        flash('Invalid admin credentials.')
        return redirect(url_for('homepage'))


@app.route('/adminpage')
@login_required
def adminpage():
    return render_template('adminpage.html')


@app.route('/addingbook', methods=['POST'])
def addingbook():
    if Books.query(Books.name == request.form['bookname']).get():
        if Books.query(Books.author == request.form['authorname']).get():
            flash('This book is already in our list.')
            return redirect(url_for('adminpage'))
    addbook = Books(name=request.form['bookname'], genre=request.form['genre'], author=request.form['authorname'])
    addbook.put()
    flash("Book added successfully")
    return render_template('adminpage.html')


@app.route('/adminlogout')
def adminlogout():
    session.pop('logged_in', None)
    return redirect(url_for('homepage'))


@app.route('/forgot')
def forgot():
    return render_template('forgotpassword.html')


@app.route('/forgotpassword', methods=['POST'])
def forgotpassword():
    mailid = request.form['mail']
    uid = str(uuid.uuid4())
    utc = pytz.UTC
    timestamp = datetime.now().replace(tzinfo=utc)
    timestamp = timestamp.time()
    sender = str("saipavan.sankar@adaptavantcloud.com")
    confirmation = ForgotPassword(id=mailid, email=mailid, uid=uid, timestamp=timestamp)
    confirmation.put()
    subject = str('Reset Password - link')
    link = 'https://workwithflask.appspot.com/resetpassword/{}&id={}'.format(uid, mailid)
    mail.send_mail(sender, mailid, subject, link)
    flash('Reset Password Link has been sent to your Email,Please check within 10 mins')
    return redirect(url_for('homepage'))


@app.route('/resetpassword/<uid>&<mailid>')
def resetpassword(uid, mailid):
    logging.info(uid)
    uid = uid
    id = mailid
    # logging.info(id)
    uid_key = ForgotPassword.query(ForgotPassword.uid == uid).get()
    # logging.info(uid_key)
    timestamp = uid_key.timestamp
    # logging.info(timestamp)
    utc = pytz.UTC
    currenttime = datetime.now().replace(tzinfo=utc)
    currenttime = currenttime.time()
    # logging.info(currenttime)
    minutedifference = currenttime.minute - timestamp.minute
    # logging.info(minutedifference)
    if minutedifference <= 10:
        return render_template('resetpassword.html', uid=uid)
    else:
        return 'session expired'


@app.route('/resetpasswordstore', methods=['POST'])
def resetpasswordstore():
    mail = request.form['mail']
    uid = request.form['uid']
    entity_key = ForgotPassword.query(ForgotPassword.email == mail).get()
    # logging.info(entity_key)
    originaluid = entity_key.uid
    if uid == originaluid:
        if request.form['password'] == request.form['reenterpassword']:
            user = UserDetails.query(UserDetails.email_ID == mail).get()
            logging.info(user)
            newpassword = request.form['password']
            newpassword = generate_password_hash(newpassword)
            user.password = newpassword
            # logging.info(user.password)
            user.put()
            flash('Password reset Sucessfully')
            return redirect(url_for('homepage'))
        else:
            return 'Type correct password'
    else:
        return 'Don\'t try to change the uid'


books_per_page = 2
key = 'anykey'

@app.route('/getbooks')
def getbooks():
    if key == request.headers.get('key'):
        cursor = Cursor(urlsafe = request.args.get('cursor'))
        data, next_cursor, more = Books.query().fetch_page(books_per_page, start_cursor=cursor)
        dic = []
        for book in data:
            x = book.key.id()
        dic.append({x: {'name': book.name, 'genre': book.genre, 'author': book.author}})
        # if more or next_cursor:
        book = {'books': dic, "cursor": next_cursor.urlsafe(), "more": more}
        return jsonify(book)
    # else:
    #     return make_response(jsonify({'error': 'Invalid secret_key'}), 404)


if __name__ == '__main__':
    app.run(debug=True)