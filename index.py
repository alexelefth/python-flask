from flask import Flask, render_template, request, session, url_for, redirect, abort, flash
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user
from is_safe_url import is_safe_url

UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

# session requirements
app.secret_key = 'MySecretCombinationIsaMysteryForYou'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# csrf protection
csrf = CSRFProtect()
csrf.init_app(app)
app.config['WTF_CSRF_ENABLED'] = True

# bcrypt hashes
bcrypt = Bcrypt(app)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "/login"  # when unauthenticated, user will be redirected here

class User:
    def __init__(self, userID):
        self.userID = userID

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.userID

@app.route('/')
@login_required
def index():
    username = session['username']
    admin = session['admin']
    if admin:
        return render_template('admin/index.html', username=username, admin=admin, session_active=True,
                               user_id=session['userID'])
    else:
        return render_template('users/index.html', username=username, admin=admin, session_active=True,
                               user_id=session['userID'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # user input
        username = request.form['username']
        password = request.form['password']
        hash = bcrypt.generate_password_hash(password)

        # api call goes here
        #res = "api response"
        #response_list = res.json()

        # check api response
        #if response_list:
        #    db_user = response_list['username']
        #    db_password = response_list['password']
        #    db_role = response_list['role']
        #    db_userID = response_list['userID']

            new_user = User(str(db_userID))
        else:
            return redirect(url_for('login'))

        # check for credentials here
        if (username == db_user) and (bcrypt.check_password_hash(hash, db_password)):
            login_user(new_user)
            session['username'] = db_user
            session['userID'] = db_userID
            if db_role == "admin":
                session['admin'] = 1
            else:
                session['admin'] = 0
            next = request.args.get('next', '/')
            # is_safe_url should check if the url is safe for redirects.
            if not is_safe_url(next, {"localhost:5000", "localhost:3000"}):
                return abort(400)
            return redirect(url_for('index'))
        else:
            return redirect(url_for('login'))
    return render_template('login.html', session_inactive=True)

@app.route('/logout')
@login_required
def logout():
    # remove the session attributes and logout user
    session.pop('username', None)
    session.pop('admin', None)
    session.pop('userID', None)
    logout_user()
    return redirect(url_for('login'))
    
# File upload part
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
           
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_photo():
    username = session['username']
    admin = session['admin']
    if admin:
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                print('No file part')
                return redirect(request.url)
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                print('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = username + "." + filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return render_template('admin/upload_photo.html', admin=admin, username=username, user_id=session['userID'])           
