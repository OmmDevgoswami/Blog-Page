from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
import hashlib
from flask_login import login_required
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from functools import wraps
from flask import abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
import dotenv
dotenv.load_dotenv()

FLASK_SECRETS = os.getenv("FLASK_SECRETS")

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRETS
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)

# TODO: Configure Flask-Login
from functools import wraps
from flask import abort
from flask_login import current_user

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            abort(403)  
        return f(*args, **kwargs)
    return decorated_function

def editor_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['editor', 'admin']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def dicebear_avatar(seed, style="adventurer", size=60):
    hash_str = hashlib.md5(seed.strip().lower().encode('utf-8')).hexdigest()
    return f"https://api.dicebear.com/7.x/{style}/svg?seed={hash_str}&size={size}"

app.jinja_env.globals['avatar'] = dicebear_avatar

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///new_posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id : Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"))
    user = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # author: Mapped[str] = mapped_column(String(250), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    
    comments = relationship("Comments", back_populates="post")

# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    role: Mapped[str] = mapped_column(String(50), default="user")
    
    posts = relationship("BlogPost", back_populates="user")
    comments = relationship("Comments", back_populates="user")
    
class Comments(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    postId: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_post.id"))
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"))
    text: Mapped[str] = mapped_column(Text, nullable=False)
    
    post = relationship("BlogPost", back_populates="comments")
    user = relationship("User", back_populates="comments")

with app.app_context():
    db.create_all()

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods = ["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if request.method == "POST":
            email = request.form.get("email")
            existing_user = User.query.filter_by(email=email).first()
            
            if existing_user:
                flash("User already exists! Please log in.")
                return redirect(url_for('login'))
            
            new_user = User(
                email=request.form.get("email"),
                password=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8),
                name=request.form.get("name"),
                role="user"
            )
            
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("Registration Successful")
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods = ["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            user = User.query.filter_by(email=email).first()
            
            if not user:
                flash("Wrong Credentials Entered!! Please try again.")
                return redirect(url_for('login'))
            
            if not check_password_hash(user.password, password):
                flash("Wrong Credentials Entered!! Please try again.")
                return redirect(url_for('login'))
            
            login_user(user)
            return redirect(url_for('get_all_posts'))
        flash("Login Successful")
        return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    blogs = db.session.execute(db.select(BlogPost)).scalars().all()
    return render_template("index.html", all_posts=blogs)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods = ["GET", "POST"])
def show_post(post_id):
    comments = db.session.execute(db.select(Comments).where(Comments.postId == post_id)).scalars().all()
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment.")
            return redirect(url_for('login'))
        
        new_comment = Comments(
            text = form.comment.data,
            postId = post_id,
            user = current_user
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id = post_id))
    return render_template("post.html", post = requested_post, comments=comments, form=form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@editor_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            user=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@editor_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        user=post.user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.user = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete_comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comments, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment_to_delete.postId))

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

if __name__ == "__main__":
    app.run(debug=False, port=5002)
