from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class NewBlogForm(FlaskForm):
    title = StringField('Blog Post Title*', validators=[DataRequired(
        message='Blog Title is required'), Length(min=1, max=245, message='Blog title must be 1-245 characters long')])

    subtitle = StringField('Subtitle*', validators=[DataRequired(
        message='Subtitle is required'), Length(min=1, max=245, message='Blog subtitle must be 1-245 characters long')])

    img_url = StringField('Blog Image URL*', validators=[DataRequired(
        message="Blog Image is required"), Length(min=1, max=245, message='URL must be 1-245 characters long'), URL(message='Invalid URL')])

    body = CKEditorField('Blog Content*', validators=[
        DataRequired(message="Blog Content is required")])

    submit = SubmitField('Create Blog')


# WTForm for to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[
                        DataRequired(message='Email is required')])
    password = PasswordField("Password", validators=[
                             DataRequired(message='Password is required')])
    name = StringField("Name", validators=[DataRequired('Name is required')])
    submit = SubmitField("Register Me!")


# WTForm for to login users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
                        DataRequired(message='Enter Email')])
    password = PasswordField("Password", validators=[
                             DataRequired(message='Enter Password')])
    submit = SubmitField("Log in!")


# WTForm for creating a comments on blog post
class AddCommentForm(FlaskForm):
    comment = StringField('Add Comment', validators=[DataRequired(
        message='write some content to add comment')])

    submit = SubmitField('Comment')
