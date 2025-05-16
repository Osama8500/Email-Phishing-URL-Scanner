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

def create_superadmin():
    with app.app_context():
        # Check if admin exists
        admin = User.query.filter_by(username="Osama_078").first()
        if admin:
            print("Admin already exists!")
            # Update admin privileges just in case
            admin.is_admin = True
            db.session.commit()
            print("تم تحديث الصلاحيات بنجاح!")
            print(f"اسم المستخدم: {admin.username}")
            print(f"البريد الإلكتروني: {admin.email}")
            return

        # Create new admin
        admin = User(
            username="Osama_078",
            email="osamakhammad@gmail.com",
            is_admin=True
        )
        admin.set_password("Osama@078#")
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        print("Superadmin created successfully!")

if __name__ == "__main__":
    create_superadmin() 