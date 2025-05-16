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

def check_and_reset_user():
    with app.app_context():
        # Check for user with either username
        user = User.query.filter_by(username='osama').first() or User.query.filter_by(username='Osama_078').first()
        
        if user:
            print(f"تم العثور على المستخدم: {user.username}")
            print(f"البريد الإلكتروني: {user.email}")
            print(f"هل هو مشرف؟ {'نعم' if user.is_admin else 'لا'}")
            
            # Reset password
            user.set_password("osama078")
            db.session.commit()
            print("\nتم إعادة تعيين كلمة المرور بنجاح!")
            print("اسم المستخدم:", user.username)
            print("كلمة المرور الجديدة: osama078")
        else:
            print("لم يتم العثور على المستخدم!")
            # Create new user
            new_user = User(
                username="osama",
                email="osama@example.com",
                is_admin=True
            )
            new_user.set_password("osama078")
            db.session.add(new_user)
            db.session.commit()
            print("\nتم إنشاء حساب جديد!")
            print("اسم المستخدم: osama")
            print("كلمة المرور: osama078")

if __name__ == "__main__":
    check_and_reset_user() 