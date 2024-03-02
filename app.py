from flask import Flask, redirect, url_for, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin , AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
from getpass import getpass
import hashlib
import random
import sys
from waitress import serve
import configparser

config = configparser.RawConfigParser()
config.read('.config')

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///data.db'
app.config['SECRET_KEY'] = config['app']['secret']

db = SQLAlchemy(app)
login = LoginManager(app)

def sha512(str):
    h = hashlib.sha512(str.encode('utf-8'))
    return h.hexdigest()

@login.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@login.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True)
    displayName = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(200))
    preferences = db.Column(db.Text, default='')
    hasDrawn = db.Column(db.Integer, default=0)
    wasDrawn = db.Column(db.Integer, default=0)
    isAdmin = db.Column(db.Boolean)
    participates = db.Column(db.Boolean, default=False)

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.isAdmin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class MyAdminIndexView(AdminIndexView):
    @expose('/', methods=('GET', 'POST'))
    def index_view(self):
        return self.render('admin/index.html')

    def render(self, template, **kwargs):
        return super(AdminIndexView, self).render('admin/index.html', **kwargs)

    def is_accessible(self):
        return current_user.is_authenticated and current_user.isAdmin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))

@app.route('/')
@login_required
def index():
    if not current_user.participates:
        return render_template('index.html', alerts=[('error', 'You are not currently participating.')])
    return render_template('index.html', preferences=current_user.preferences, participating=current_user.participates)

@app.route('/', methods=['POST'])
@login_required
def indexPost():
    if not current_user.participates:
        return render_template('index.html', alerts=[('error', 'You are not currently participating.')])

    preferences = request.form['preferences'] or None
    if not preferences:
        # I am too lazy for an error. There is an 'required' set within the textarea, stop fiddling with the HTML.
        return render_template('index.html')
    current_user.preferences = preferences
    db.session.commit()

    # Check if user already has drawn a person
    # if not, draw a person randomly.
    if current_user.hasDrawn == 0:
        # User has not yet drawn a person
        undrawn = User.query.filter(User.id != current_user.id).filter(User.wasDrawn == 0).filter(User.participates == True).all()
        # If there are only two persons left, we chose one that hasn't drawn yet.
        if len(undrawn) == 2:
            if undrawn[0].hasDrawn == 0:
                tmpPerson = undrawn[0]
            else:
                tmpPerson = undrawn[1]
        # Otherwise we just chose one at random
        else:
            if (len(undrawn) > 0):
                tmpPerson = undrawn[random.randint(0, len(undrawn) - 1)]
            else:
                alerts = []
                alerts.append(['Error:','You have to add users first. This is not a single-player game.'])
                return render_template('index.html', preferences=current_user.preferences, alerts=alerts, participating=current_user.participates)
        tmpPerson.wasDrawn = current_user.id
        current_user.hasDrawn = tmpPerson.id
        db.session.commit()
        person = tmpPerson
    else:
        person = User.query.filter_by(id=current_user.hasDrawn).first()

    return render_template('index_submitted.html', person=person.displayName, preferences=person.preferences, participating=current_user.participates)

@app.route('/login', methods=['GET'])
def loginForm():
    if current_user.is_authenticated and current_user.isAdmin:
        return redirect(url_for('admin.index'))
    elif current_user.is_authenticated:
        return redirect('/')
    return render_template('login_form.html')

@app.route('/login', methods=['POST'])
def login():
    name = request.form['name'] or None
    password = request.form['password'] or None

    if name and password:
        password = sha512(password)

        users = User.query.all()
        for user in users:
            if name == user.name and password == user.password:
                login_user(user)
                if user.isAdmin:
                    return redirect(url_for('admin.index'))
                else:
                    return redirect('/')
    
    alerts = []
    alerts.append(['Error:','Login is invalid.'])
    return render_template('login_form.html', alerts=alerts)

@app.route('/register', methods=['GET'])
def registerForm():
    if current_user.is_authenticated and current_user.isAdmin:
        return redirect(url_for('admin.index'))
    elif current_user.is_authenticated:
        return redirect('/')
    return render_template('register_form.html')

@app.route('/register', methods=['POST'])
def register():
    name = request.form['name'] or None
    password = request.form['password'] or None
    repeatPassword = request.form['repeatPassword'] or None

    if password != repeatPassword:
        alerts = []
        alerts.append(['Error:','Passwords do not match.'])
        return render_template('register_form.html', alerts=alerts)

    if name and password:
        password = sha512(password)

        users = User.query.all()
        if not name in [user.name for user in users]:
            user = User(name=name, displayName=name, password=password, isAdmin=False, participates=False)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect('/')
    
    alerts = []
    alerts.append(['Error:','An error occured.'])
    return render_template('register_form.html', alerts=alerts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if User.query.count() < 1:
            uname = input('Enter admin name: ')
            upassword = getpass('Enter admin password: ')
            upassword = sha512(upassword)
            admin = User(name=uname, displayName=uname, password=upassword, isAdmin=True)
            db.session.add(admin)
            db.session.commit()
    if len(sys.argv) >= 2 and sys.argv[1] == 'dev':
        app.run(debug=True)
    else:
        serve(app, host='0.0.0.0', port=config['app']['port'])