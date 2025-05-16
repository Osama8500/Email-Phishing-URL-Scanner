from app import app, db, User

with app.app_context():
    user = User.query.filter_by(username="Osama").first()
    if user:
        print(f"اسم المستخدم: {user.username}")
        print(f"البريد الإلكتروني: {user.email}")
        print(f"حالة المشرف: {user.is_admin}")
    else:
        print("المستخدم غير موجود") 