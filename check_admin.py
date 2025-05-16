from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)

with app.app_context():
    # البحث عن المستخدم
    user = User.query.filter_by(username="Osama_078").first()
    if user:
        print("معلومات المستخدم:")
        print(f"اسم المستخدم: {user.username}")
        print(f"البريد الإلكتروني: {user.email}")
        print(f"هل هو مشرف؟ {'نعم' if user.is_admin else 'لا'}")
        print(f"التحقق من كلمة المرور 'Osama@078#':", check_password_hash(user.password_hash, "Osama@078#"))
    else:
        print("المستخدم غير موجود في قاعدة البيانات!") 