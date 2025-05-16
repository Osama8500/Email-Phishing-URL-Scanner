from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

with app.app_context():
    # إنشاء المشرف
    admin = User(username="Osama_078", email="osamakhammad@gmail.com", is_admin=True)
    admin.set_password("Osama@078#")
    db.session.add(admin)
    db.session.commit()
    print("تم إنشاء حساب المشرف بنجاح!")

    admin = User.query.filter_by(username="Osama_078").first()
    if admin:
        admin.is_admin = True
        db.session.commit()
        print("تم تحديث صلاحيات المشرف بنجاح!") 