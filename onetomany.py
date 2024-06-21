from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from sqlalchemy.exc import IntegrityError
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)


class Post(db.model):
    id = Mapped[Integer] = mapped_column(Integer, primary_key=True)
    title = Mapped[String] = mapped_column(String(100))
    subtitle = Mapped[String] = mapped_column(String(1000))
    comments = db.relationship('P')

class Comment(db.Model):
    id = Mapped[Integer] = mapped_column(Integer, primary_key=True)
    title = Mapped[String] = mapped_column(String(100))
    body = Mapped[String] = mapped_column(String(100))

