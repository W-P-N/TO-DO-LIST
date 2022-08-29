import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import Form, StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug import security as hash
from flask_login import LoginManager, login_required, login_user, UserMixin, current_user, logout_user

to_do_list = Flask(__name__)  # Creating Flask app
# Database code - SQLAlchemy
to_do_list.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///to_do.db'  # Configuring application with sqlalchemy and
# naming db file
db = SQLAlchemy(app=to_do_list)  # Creating database object by passing in the object

login_manager = LoginManager()  # Instance of class login manager.
login_manager.init_app(to_do_list)  # Configuration of application with Login Manager
to_do_list.secret_key = os.environ.get('TODOLIST_KEY')


# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Creating User class to create database
class User(UserMixin, db.Model):  # Model class is used to declare model that will be the design for our database
    id = db.Column(db.Integer, primary_key=True)  # Assigns integer for each row in database, hence called primary key.
    username = db.Column(db.String(30), nullable=False, unique=False)  # Nullable states that this field cannot be
    # kept and entered empty in the database. Unique boolean states if username should be unique or not.
    emailid = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(100), unique=True, nullable=False)
    tasks = db.relationship('Tasks', backref='user')  # Each user will have their set of tasks, Here 'tasks' will create
    # a relationship between 'user' and his 'tasks'.


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


# db.create_all()  # Creates tables and databases
all_tasks = db.session.query(Tasks).all()
print(all_tasks)
user_data = User.query.all()
# Flask Form code
csrf_token = os.environ.get("CSRF_TOKEN")  # Creating csrf token to access forms as we switch templates
to_do_list.config['SECRET_KEY'] = csrf_token  # Configuring application with csrf key and so to Flask Form


# Login Form
class Loginform(FlaskForm):
    email = EmailField('EMAIL-ID:', validators=[DataRequired()])
    password = PasswordField('PASSWORD:', validators=[DataRequired()])
    login = SubmitField('LOGIN')


# Signup Form
class Signup(FlaskForm):
    name = StringField("NAME:", validators=[DataRequired(), Length(min=4, max=10)])
    email = EmailField('EMAIL-ID:', validators=[DataRequired()])
    password = PasswordField('SET PASSWORD:', validators=[DataRequired()])
    signup_button = SubmitField('SIGNUP')


# A form to add task in to do list
class TaskForm(FlaskForm):
    task = StringField("TASK:", validators=[DataRequired()])
    add_task = SubmitField("ADD TASK")


# Function to hash passwords:
def hash_password(password):
    hashed_password = hash.generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
    return hashed_password


# Function to unhash passwords:
def check_hash(user_hash, password):
    check = hash.check_password_hash(user_hash, password)
    return check


# Flask form code end

# Routes:
@to_do_list.route("/")  # Home Route Decorator
def home():
    print(current_user.is_authenticated)
    return render_template("index.html", user_logged_in=current_user.is_authenticated)


@to_do_list.route("/login", methods=["POST", "GET"])  # Specifying methods
def login():
    form = Loginform()  # Creating instance of form
    if form.validate_on_submit():  # Validates the form
        for user in user_data:  # Scanning through database
            if user.emailid == form.email.data:
                if check_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('main_application',
                                            user_logged_in=current_user.is_authenticated))  # If user details are in the database
        else:
            flash("Incorrect Email-ID or Password")

    return render_template("login.html", form=form, user_logged_in=current_user.is_authenticated)


@to_do_list.route("/signup", methods=["POST", "GET"])
def signup():
    form = Signup()
    if form.validate_on_submit():  # If form is validated:
        hashed_password = hash_password(form.password.data)
        new_user = User()  # Create instance of User class
        new_user.emailid = form.email.data
        new_user.username = form.name.data
        new_user.password = hashed_password
        db.session.add(new_user)  # Adding user data to database
        db.session.commit()  # Committing changes to database
        login_user(new_user)
        return redirect(url_for("main_application", user_logged_in=current_user.is_authenticated))
    return render_template("signup.html", form=form, user_logged_in=current_user.is_authenticated)


@to_do_list.route("/to-do-list", methods=["POST", "GET"])
@login_required
def main_application():
    print(current_user.id)
    form = TaskForm()
    if form.validate_on_submit() and request.method == "POST":
        new_task = Tasks()
        new_task.task = form.task.data
        new_task.user_id = current_user.id
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for('main_application', user_logged_in=current_user.is_authenticated, tasks_list=all_tasks,
                                id=current_user.id))
    return render_template("main_application.html", form=form, user_logged_in=current_user.is_authenticated,
                           tasks_list=all_tasks, id=current_user.id)


@to_do_list.route("/del/<int:id>")
@login_required
def delete_task(id):
    del_task = Tasks.query.get(id)
    db.session.delete(del_task)
    db.session.commit()
    return redirect(url_for('main_application'))


@to_do_list.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home', user_logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    to_do_list.run(debug=True)
