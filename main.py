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
from flask_mail import Mail, Message
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, OtpVerify
import os



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# Adding some more config for the otp verification
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL')
app.config['MAIL_PASSWORD'] = os.environ.get('PASSWORD_EMAIL')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


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

        otp = send_verification_mail()

        session['registration_data'] = {
            'email':email,
            "password": password,
            'name' : name,
            'otp': str(otp)
        }
        session['registration_initiated'] = True

        return redirect(url_for('verification'))

    return render_template("register.html", form=registration, current_user=current_user)


@app.route("/verification", methods=['POST', 'GET'])
def verification():
    if not session.get('registration_initiated'):
        flash('Access Denied', category='error')
        return redirect(url_for('register'))

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



def send_verification_mail():
    recipient = session.get('registration_data')['email']
    subject = 'OTP For Blog Journey'
    with app.open_resource('templates/otp_mail.html') as f:
        html_content = f.read().decode('utf-8')

    otp = random.randint(100000, 999999)
    name = session.get('registration_data')['name']
    html_content = html_content.replace('{{ OTP }}', str(otp))
    html_content = html_content.replace('{{ NAME }}', name)

    message = Message(subject, recipients=[recipient])
    message.html = html_content
    try:
        mail.send(message)
        flash("OTP SENT SUCCESSFULLY")
        return otp
    except Exception as e:
        print(f"Error sending email: {e}")



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
    app.run(debug=True)
