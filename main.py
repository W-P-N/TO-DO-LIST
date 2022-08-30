import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug import security as s
from flask_login import LoginManager, login_required, login_user, UserMixin, current_user, logout_user


to_do_list = Flask(__name__)  # Creating a Flask application

login_manager = LoginManager()  # Creating instance of login manager to add authentication functionality.

to_do_list.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///to_do.db")  # Configuring
# application with sqlalchemy.
to_do_list.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Set track modifications in database to false.
login_manager.init_app(to_do_list)  # Configuring application with Login Manager

# CONSTANTS:
to_do_list.secret_key = os.environ.get("TODOLIST_KEY")  # Creating a secret key to protect sessions
csrf_token = os.environ.get("CSRF_TOKEN")  # Creating csrf token to access forms as we switch templates

db = SQLAlchemy(app=to_do_list)  # Creating database object and configuring it with application


# User loader callback
@login_manager.user_loader
def load_user(user_id):
    """Loads user object to create a token for each session."""
    return User.query.get(int(user_id))


# Creating two classes: user and tasks with one-to-many relationship. One user will have their list of tasks.
class User(UserMixin, db.Model):
    """This class defines users for our database.
    Model class is used to declare model that will be the design for our table in database and allows us to declare
    functions such as read, write, edit and delete data in out tables.
    UserMixin class from flask-login allows us to declare authentication functions such as is_authenticated() etc."""
    id = db.Column(db.Integer, primary_key=True)  # Assigns integer for each row in database: primary key.
    username = db.Column(db.String(30), nullable=False, unique=False)  # Nullable states that this field cannot be
    # kept and entered empty in the database. Unique boolean states if username should be unique or not.
    usr_email_id = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(100), unique=True, nullable=False)
    tasks = db.relationship('Tasks', backref='user')  # Each user will have their set of tasks, Here 'tasks' will create
    # a relationship between 'user' and his 'tasks'.


class Tasks(db.Model):
    """This class designs the table for tasks along with the id of user who entered that task."""
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # This column in table stores the id of user who created
    # the task.


# db.create_all()  # Creates tables and databases.... Commented out because database is already created.

users_list = User.query.all()  # Getting the list of all users in the database.

to_do_list.config['SECRET_KEY'] = csrf_token  # Configuring application with csrf key.


# Flask Form code:
#   Login Form -
class Loginform(FlaskForm):
    """This class creates a login form."""
    email = EmailField('EMAIL-ID:', validators=[DataRequired()])
    password = PasswordField('PASSWORD:', validators=[DataRequired()])
    login = SubmitField('LOGIN')


#   Signup Form -
class Signup(FlaskForm):
    """This class creates a signup form."""
    name = StringField("NAME:", validators=[DataRequired(), Length(min=4, max=10)])
    email = EmailField('EMAIL-ID:', validators=[DataRequired()])
    password = PasswordField('SET PASSWORD:', validators=[DataRequired()])
    signup_button = SubmitField('SIGNUP')


#   Add task Form-
@login_required  # This decorator checks if the user is logged in to add their task.
class TaskForm(FlaskForm):
    """This class creates a form to get task from user"""
    task = StringField("TASK:", validators=[DataRequired()])
    add_task = SubmitField("ADD TASK")


# Function to hash passwords:
def hash_password(password):
    """This function hashes the user password. Converts password to SHA256 hash string with salt of length 8."""
    hashed_password = s.generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
    return hashed_password


# Function to un-hash passwords:
def check_hash(user_hash, password):
    """This function checks if the password entered by the user is correct by comparing hashes."""
    check = s.check_password_hash(user_hash, password)
    return check  # Returns boolean


# Function to get all tasks in the database:
def get_tasks():
    all_tasks = db.session.query(Tasks).all()  # Getting the list of all tasks in the database.
    return all_tasks


# Routes:
@to_do_list.route("/")  # Home Route.
def home():
    """This function loads a home page."""
    return render_template("index.html", user_logged_in=current_user.is_authenticated)  # Loads the index.html template.
    # Passing user_logged_in argument to check if the user is logged in and make changes accordingly in the template
    # using jinja.


@to_do_list.route("/login", methods=["POST", "GET"])  # Login Route.
def login():
    """This function loads the login page."""
    form = Loginform()  # Creating object of class Login-form.
    if form.validate_on_submit():  # Validates the form: Checks if data entered by user satisfies the in-built/
        # programmer defined conditions.
        for user in users_list:  # Scanning through database.
            if user.usr_email_id == form.email.data:  # Checks if the email ids match.
                if check_hash(user.password, form.password.data):  # Checks if the passwords match check_hash function.
                    login_user(user)  # Logs in the user and returns true for is_authenticated.
                    return redirect(url_for('main_application',
                                            user_logged_in=current_user.is_authenticated))  # Loads main app page.
            else:
                flash("Incorrect Email-ID or Password")  # Flashes if the credentials are incorrect or user missing.

    return render_template("login.html", form=form, user_logged_in=current_user.is_authenticated)  # Sends form as
    # argument to create form in html. If method is get, this command will be executed.


@to_do_list.route("/signup", methods=["POST", "GET"])  # Signup route.
def signup():
    """This function loads the signup page."""
    form = Signup()  # # Creating object of class Signup form.
    if form.validate_on_submit():  # If form is validated:
        hashed_password = hash_password(form.password.data)  # Calling hash_password function to hash data obtained
        # from the user.
        new_user = User()  # Create instance of User class to add user in database table.
        new_user.usr_email_id = form.email.data  # Entering email-id in the database.
        new_user.username = form.name.data  # Entering username in the database.
        new_user.password = hashed_password  # Entering hashed password in the database (Even programmer won't
        # know the password).
        db.session.add(new_user)  # Adding user data to database.
        db.session.commit()  # Committing changes to database.
        login_user(new_user)  # Logging in the user and redirecting them to application.
        return redirect(url_for("main_application", user_logged_in=current_user.is_authenticated))
    return render_template("signup.html", form=form, user_logged_in=current_user.is_authenticated)  # If method is get,
    # this command will be executed.


@to_do_list.route("/to-do-list", methods=["POST", "GET"])  # Main Application Route.
@login_required  # This decorator checks if the user is logged in to enter the main_application.
def main_application():
    """This function loads the main application."""
    form = TaskForm()  # Creating form instance.
    if form.validate_on_submit() and request.method == "POST":  # Specifying conditions.
        new_task = Tasks()  # Creating object of class Task().
        new_task.task = form.task.data  # Entering task name.
        new_task.user_id = current_user.id  # Entering the id of user who entered that task.
        db.session.add(new_task)  # Adding new task to database.
        db.session.commit()  # Committing changes to database.
        return redirect(url_for('main_application', user_logged_in=current_user.is_authenticated,
                                tasks_list=get_tasks(),
                                id=current_user.id))  # Redirects user to same application, with all the tasks in the
        # list
    return render_template("main_application.html", form=form, user_logged_in=current_user.is_authenticated,
                           tasks_list=get_tasks(), id=current_user.id)  # If method is get,
    # this command will be executed.


@to_do_list.route("/del/<int:id>")  # Delete task Route.
@login_required  # This decorator checks if the user is logged in to delete task.
def delete_task(tsk_id):  # Passing in the task id that is to be deleted.
    del_task = Tasks.query.get(tsk_id)  # Getting the task from database using task id.
    db.session.delete(del_task)  # Deleting task from the database.
    db.session.commit()  # Committing changes.
    return redirect(url_for('main_application'))  # Redirecting user back to main application.


@to_do_list.route("/logout")  # Logout Route.
@login_required  # This decorator checks if the user is logged in to log out and end the session.
def logout():
    logout_user()  # Logs-out the user.
    return redirect(url_for('home', user_logged_in=current_user.is_authenticated))  # Redirects back to home page.


if __name__ == "__main__":  # If name of the running script is __main__, then the application will run.
    to_do_list.run()
