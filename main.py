import random
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, OtpVerify, ResetPassword, ResetForm
import os
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Adding the new mail configuration
config = sib_api_v3_sdk.Configuration()
config.api_key['api-key'] = os.environ.get('EMAIL_API')
api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(config))


ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)



# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI','sqlite:///usage.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Creating the User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Creating an admin only decorator function
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)

        return f(*args, **kwargs)
    return decorated_function



# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))

    author = relationship("User", back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


with app.app_context():
    db.create_all()


def generate_otp():
    return random.randint(100000,999999)


@app.route('/register', methods=["POST", "GET"])
def register():
    registration = RegisterForm()
    if registration.validate_on_submit():
        email = registration.email.data
        password = generate_password_hash(password=registration.password.data, method="pbkdf2:sha256", salt_length=8)
        name = registration.name.data
        user = User.query.filter_by(email=email).first()
        if user:
            flash("You have already registered. Log in instead", category="error")
            return redirect(url_for("login"))

        otp = generate_otp()

        session['registration_data'] = {
            'email':email,
            "password": password,
            'name' : name,
            'otp': str(otp)
        }

        send_verification_mail(session['registration_data'])

        return redirect(url_for('verification'))

    return render_template("register.html", form=registration, current_user=current_user)


@app.route("/verification", methods=['POST', 'GET'])
def verification():
    verification = OtpVerify()
    if verification.validate_on_submit():

        user_input = verification.otp_verify.data

        registration_data = session.get('registration_data')
        if user_input == registration_data['otp']:

            # Creating a new User

            email = registration_data['email']
            password = registration_data['password']
            name = registration_data['name']
            new_user = User(email=email, password=password, name=name)
            # Checking if we are able to add the new_user
            # If not then the user already exists.

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))

        else:
            flash('Invalid OTP\nRedirecting to the Registration Page')
            return redirect(url_for('register'))
    return render_template("register.html", form=verification, current_user=current_user)



def send_verification_mail(registration_data):
    subject = 'OTP for Blog Journey'
    sender = {"name": "Aditya", "email": os.environ.get('EMAIL')}
    with open("templates/otp_mail.html", encoding="utf-8") as file:
        html_content = file.read()

    html_content = str(html_content)
    otp = registration_data['otp']
    username = registration_data['name']
    html_content = html_content.replace('{{ OTP }}', str(otp))
    html_content = html_content.replace('{{ NAME }}', username)

    recipient = [{"email": registration_data['email'], "name": "TO PERSON"}]

    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(to=recipient, html_content=html_content, sender=sender,
                                                   subject=subject)

    try:
        # Send the email
        api_response = api_instance.send_transac_email(send_smtp_email)
        print(api_response)
    except ApiException as e:
        print("Exception when calling SMTPApi->send_transac_email: %s\n" % e)



# TODO: Retrieve a user from the database based on their email.
@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            check_user = check_password_hash(user.password, password)
            if check_user:
                login_user(user, remember=True)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Invalid password")
                return redirect(url_for("login"))
        else:
            flash("The User does not exist.")
            return redirect(url_for("login"))
    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


#Making the verification for the reset password
@app.route('/reset-password', methods=["POST", "GET"])
def reset_password_form():
    verification = OtpVerify()
    reset_form = ResetForm()
    if verification.validate_on_submit():

        user_input = verification.otp_verify.data
        reset_data = session.get('reset_data')
        if user_input == reset_data['otp']:

            return render_template("login.html", form=reset_form, current_user=current_user)

        else:
            flash('Invalid OTP\nRedirecting to the Registration Page')
            return redirect(url_for('register'))

    elif reset_form.validate_on_submit():
        reset_data = session.get('reset_data')
        user = User.query.filter_by(email=reset_data['email']).first()
        user.password = generate_password_hash(password=reset_form.password.data, method="pbkdf2:sha256", salt_length=8)
        db.session.commit()
        login_user(user)
        return redirect(url_for('get_all_posts'))



    return render_template("register.html", form=verification, current_user=current_user)




# Making a way to reset the password
@app.route("/reset", methods=["POST", "GET"])
def reset_password():
    reset = ResetPassword()
    if reset.validate_on_submit():
        email = reset.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            otp = generate_otp()
            session['reset_data'] = {
                'email': user.email,
                'name': user.name,
                'otp': str(otp)
            }
            send_verification_mail(session['reset_data'])

            return redirect(url_for('reset_password_form'))

        else:
            flash("The User does not exist.")
            return redirect(url_for("reset_password"))

    return render_template("reset_form.html", form=reset, current_user=current_user)


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comments = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    return render_template("post.html", post=requested_post, current_user=current_user, comment_form=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=False)
