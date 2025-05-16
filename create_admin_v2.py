from app import app, db, User

def create_admin():
    with app.app_context():
        try:
            # حذف المستخدم إذا كان موجوداً
            existing_user = User.query.filter_by(username="Osama_078").first()
            if existing_user:
                db.session.delete(existing_user)
                db.session.commit()
                print("تم حذف المستخدم القديم")

            # إنشاء مستخدم جديد
            admin = User(
                username="Osama_078",
                email="osamakhammad@gmail.com",
                is_admin=True
            )
            admin.set_password("Osama@078#")
            db.session.add(admin)
            db.session.commit()
            print("تم إنشاء حساب المشرف بنجاح!")

            # التحقق من إنشاء المستخدم
            new_admin = User.query.filter_by(username="Osama_078").first()
            if new_admin and new_admin.is_admin:
                print("تم التحقق من صلاحيات المشرف")
            else:
                print("حدث خطأ في إعداد صلاحيات المشرف")

        except Exception as e:
            print(f"حدث خطأ: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    create_admin() 