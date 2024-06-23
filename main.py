from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from sqlalchemy.exc import IntegrityError
from threading import Thread
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ForgotPass, ForgotPassApproval, NewPassword
from flask_gravatar import Gravatar
from dotenv import load_dotenv
import os
import random
from flask_mail import Mail, Message


load_dotenv()

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

secret_key = os.getenv('SECRET_KEY')
database_url = os.getenv('DATABASE_URL')
secret_email = os.getenv('SECRET_EMAIL')
app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gald12123434@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv('SECRET_EMAIL')
app.config['MAIL_DEFAULT_SENDER'] = ('Gal Dadon', 'gald12123434@gmail.com')
mail = Mail(app)            
ckeditor = CKEditor(app)

def send_async_email(msg):
    with app.app_context():
        mail.send(msg)

Bootstrap5(app)

# TODO: Configure Flask-Login
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)        
    return decorated_function



# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app=app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    comments = relationship('Comment', back_populates='post_comments')
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)




# TODO: Create a User table for all your registered users. 
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')

class Comment(db.Model):
    __tablename__ = 'comments'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'))
    comment_author = relationship('User', back_populates='comments')
    post_comments = relationship('BlogPost', back_populates='comments')
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey('blog_posts.id'))

class ForgotPassLimitedTime(db.Model):
    __tablename__ = 'limitedtimepasscode'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    limited_email = db.Column(db.String, nullable=False)
    limited_passcode = db.Column(db.Integer, nullable=False)
    session_id = db.Column(db.Integer)

with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = request.form.get('password')
        email = request.form.get('email')
        name = request.form.get('name')
        hashed_password = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=email,
            name=name,
            password=hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            flash('Email is already in use. Please try a different one.', 'error')
            return redirect(url_for('login'))
        else:
            login_user(new_user)
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    logged_in = current_user.is_authenticated
    if logged_in:
        flash('Already logged in')
        return render_template(url_for('login', logged_in=logged_in))
    if form.validate_on_submit() and 'submit' in request.form:
        print('Logged in')
        email = request.form.get('email')
        password = request.form.get('password')
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        print(email, password, user)
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user=user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password Is Incorrect')
                return redirect(url_for('login'))
        else:
            flash('Email Does Not Exist')
            return redirect(url_for('login'))
    elif form.validate_on_submit() and 'forgot_password' in request.form:
        print("gg")
        return redirect(url_for('forgot_pass'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)

@app.route('/forgot_pass', methods=['POST', 'GET'])
def forgot_pass():
    form = ForgotPass()
    if form.validate_on_submit():
        id = ""
        for _ in range(6):
            id += str(random.randint(1, 9))
        code = ""
        for _ in range(6):
            code += str(random.randint(1, 9))
        
        email = request.form.get('email')
        try:
            user_mail = User.query.filter_by(email=email).first().email
            print(user_mail)
        except:
            flash('No Such Email!')
            return redirect(url_for('login'))
        else:
            #sending email
            msg = Message('Your Verification code for reset password in GaGex Blogs website! ', recipients=[user_mail])
            msg.body = f'Your Verification code is: {code}'

            thr = Thread(target=send_async_email, args=[msg])
            thr.start()
            #saving content to the db
            new_limited_time_entry = ForgotPassLimitedTime(
                limited_passcode=code,
                limited_email=user_mail,
                session_id=id
            )
            db.session.add(new_limited_time_entry)
            db.session.commit()
            return redirect(url_for('forgot_pass_approval', emaill=user_mail))
    return render_template('forgot_pass.html' ,form=form)

@app.route('/forgot_pass/approval/<emaill>', methods=['POST', 'GET'])
def forgot_pass_approval(emaill):
    form = ForgotPassApproval()
    
    if form.validate_on_submit():
        
        code_entered_by_user = request.form.get('code')
        user_data = ForgotPassLimitedTime.query.filter_by(limited_email=emaill).order_by(ForgotPassLimitedTime.id.desc()).first()
        user_data_session_id = int(ForgotPassLimitedTime.query.filter_by(limited_email=emaill).first().session_id)
        print(user_data)
        print(user_data.limited_passcode)
        print(code_entered_by_user)
        if user_data.limited_passcode == int(code_entered_by_user):
            print('Success')
            return redirect(url_for('res_pass', id=user_data_session_id))
        else:
            flash('Code Entered Is Incorrect, Try Again')
            return redirect(url_for('forgot_pass_approval', emaill=user_data.limited_email))

        
    return render_template('forgot_pass.html', form=form, activity='Approve')


@app.route('/reset-password/<int:id>', methods=["POST", "GET"])
def res_pass(id):
    form = NewPassword()
    if form.validate_on_submit():
        user_data = db.session.execute(db.select(ForgotPassLimitedTime).where(ForgotPassLimitedTime.session_id == id)).scalar()
        user_email = user_data.limited_email
        user_data_to_update = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        first_pass = request.form.get('new_pass')
        second_pass = request.form.get('new_pass_again')
        if first_pass == second_pass:
            hashed_password = generate_password_hash(password=first_pass, method='pbkdf2:sha256', salt_length=8)
            user_data_to_update.password = hashed_password
            db.session.delete(user_data)
            db.session.commit()
            flash('Password Has been changed successfully')
            return redirect(url_for('login'))

        else:
            flash('Passwords dont match!')
            return redirect(url_for('res_pass', id=user_data.session_id))
    return render_template('login.html', form=form)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
    is_logged_in = current_user.is_authenticated

    requested_post = db.get_or_404(BlogPost, post_id)
    if request.method == 'POST':
        if is_logged_in:
            text = request.form.get('comment_text')
            print(text)
            new_comment = Comment(
                text=text,
                post_id=requested_post.id,
                comment_author=current_user
            )
            
            db.session.add(new_comment)
            db.session.commit()
            result = Comment.query.filter_by(post_id=post_id)
            print(post_id)
            comments = result.all()
        else:
            flash('You Have To Be Logged In To Use This Feature')
            return redirect(url_for('login'))
    else:
        result = Comment.query.filter_by(post_id=post_id)
        print(post_id)
        comments = result.all()
    return render_template("post.html", post=requested_post, form=form, comments=comments, gravatar=gravatar)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author_id=current_user.id,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        else:
            flash('Log In To Use This Feature')
            return redirect(url_for('login'))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author_id=current_user.id,
        body=post.body
    )
    if edit_form.validate_on_submit():
        if current_user.id == post.author_id or current_user.id == 1:
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author_id = current_user.id
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    
    post_to_delete = db.get_or_404(BlogPost, post_id)
    if post_to_delete:
        if current_user.id == post_to_delete.author_id or current_user.id == 1:
            comment_to_delete = db.session.execute(db.select(Comment).where(post_id == post_id))
            comments_to_delete = comment_to_delete.all()
            comments_after_extracted = []
            for comment in comments_to_delete:
                comment = comment[0]
                comments_after_extracted.append(comment)
            for comment in comments_after_extracted:
                db.session.delete(comment)            
            db.session.delete(post_to_delete)
            db.session.commit()
        else:
            flash("You Are Not The Creator Of this post!")
    else:
        flash(f'There Is No Such Post with the id of {post_id}')
        return redirect(url_for('get_all_posts'))
    
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
