from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

def fix_database():
    with app.app_context():
        # إنشاء جداول قاعدة البيانات إذا لم تكن موجودة
        db.create_all()
        
        # حذف المستخدم القديم إذا وجد
        try:
            old_user = User.query.filter(User.username.in_(['osama', 'Osama', 'Osama_078'])).first()
            if old_user:
                db.session.delete(old_user)
                db.session.commit()
                print("تم حذف الحساب القديم بنجاح")
        except Exception as e:
            print(f"خطأ في حذف الحساب القديم: {str(e)}")
            db.session.rollback()

        # إنشاء حساب جديد
        try:
            new_user = User(
                username="osama",
                email="osama@example.com",
                is_admin=True,
                created_at=datetime.utcnow()
            )
            new_user.set_password("osama078")
            db.session.add(new_user)
            db.session.commit()
            print("\nتم إنشاء حساب جديد بنجاح!")
            print("معلومات الحساب:")
            print("-----------------")
            print("اسم المستخدم: osama")
            print("كلمة المرور: osama078")
            print("البريد الإلكتروني: osama@example.com")
            print("نوع الحساب: مشرف (Admin)")
            print("\nيمكنك الآن تسجيل الدخول باستخدام هذه المعلومات")
            
        except Exception as e:
            print(f"خطأ في إنشاء الحساب الجديد: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    fix_database() 