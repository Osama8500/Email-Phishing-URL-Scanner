from app import app, db, User

def update_to_admin():
    with app.app_context():
        try:
            # البحث عن المستخدم باستخدام اسم المستخدم
            user = User.query.filter_by(username="Osama"ذ).first()
            
            if user:
                # تحديث صلاحيات المستخدم ليصبح مشرف
                user.is_admin = True
                db.session.commit()
                print("تم تحديث الصلاحيات بنجاح!")
                print(f"اسم المستخدم: {user.username}")
                print(f"البريد الإلكتروني: {user.email}")
                print("الآن يمكنك تسجيل الدخول كمشرف")
            else:
                print("لم يتم العثور على المستخدم!")
                
        except Exception as e:
            print(f"حدث خطأ: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    update_to_admin() 