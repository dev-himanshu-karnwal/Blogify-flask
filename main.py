from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_ckeditor import CKEditor
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from forms import NewBlogForm, RegisterForm, LoginForm, AddCommentForm
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import relationship

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(app)

# Initializing CKEditor
app.config['CKEDITOR_PKG_TYPE'] = 'basic'
ckeditor = CKEditor(app)

# initializing loginManager
login_manager = LoginManager(app)


# User table for all your registered users
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


# Blog table
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="blog_post")


# Comment table for commennts on the blog post
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    author_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
    comment_author = relationship("User", back_populates="comments")

    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    blog_post = relationship("BlogPost", back_populates="comments")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get_or_404(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# only original commentator can delete commment
def only_commenter(function):
    @wraps(function)
    def check(*args, **kwargs):
        user = db.session.execute(db.select(Comment).where(
            Comment.author_id == current_user.id)).scalar()
        if not current_user.is_authenticated or current_user.id != user.author_id:
            return abort(403)
        return function(*args, **kwargs)
    return check


with app.app_context():
    db.create_all()


# Register new users into the User database
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        user_existing = db.session.execute(db.select(User).where(
            User.email == form.email.data)).scalar()
        if user_existing:
            flash('You are already registered with same email. Login instead')
            return redirect(url_for('login'))

        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(
            db.select(User).where(User.email == form.email.data)).scalar()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            form.password.errors.append('Incorrect password')
        else:
            form.email.errors.append('No user account with this email')

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


def convert_string_to_date(date_str):
    return datetime.strptime(date_str, '%B %d, %Y')


@app.route('/')
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    posts = sorted(posts, key=lambda post: datetime.strptime(
        post.date, '%B %d, %Y'), reverse=True)
    return render_template("index.html", all_posts=posts)


@app.route('/post/<int:post_id>', methods=['POST', 'GET'])
def show_post(post_id):
    form = AddCommentForm()
    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('Login first to comment on Blog posts')
            return redirect('login')
        if form.validate_on_submit():
            new_comment = Comment(text=form.comment.data,
                                  author_id=current_user.id,
                                  blog_post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            return redirect(f'/post/{post_id}')

    requested_post = db.get_or_404(BlogPost, post_id)
    return render_template("post.html", post=requested_post, form=form)


@app.route('/new-post', methods=['POST', 'GET'])
@login_required
@admin_only
def new_post():
    form = NewBlogForm()
    if request.method == 'POST' and form.validate_on_submit():

        new_blog = BlogPost(title=form.title.data, body=form.body.data, author_id=current_user.id,
                            subtitle=form.subtitle.data, img_url=form.img_url.data, date=datetime.today().strftime("%B %d, %Y"))
        db.session.add(new_blog)
        db.session.commit()

        return redirect(url_for('show_post', post_id=new_blog.id))

    return render_template("make-post.html", form=form)


@app.route('/edit-post/<int:post_id>', methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post_to_edit = db.get_or_404(BlogPost, post_id)
    form = NewBlogForm(
        title=post_to_edit.title,
        subtitle=post_to_edit.subtitle,
        body=post_to_edit.body,
        img_url=post_to_edit.img_url
    )
    if request.method == 'POST':
        if form.validate_on_submit():
            post_to_edit.title = form.title.data
            post_to_edit.subtitle = form.subtitle.data
            post_to_edit.body = form.body.data
            post_to_edit.img_url = form.img_url.data

            db.session.commit()
            return redirect(url_for('show_post', post_id=post_to_edit.id))

    return render_template("make-post.html", form=form, post=post_to_edit)


@app.route('/delete-post/<int:post_id>')
@login_required
@admin_only
def delete_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>/delete-comment/<int:comment_id>")
@login_required
@only_commenter
def delete_comment(post_id, comment_id):
    post_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
