import re

def load_spam_keywords(file_path='spam_keywords.txt'):
    """تحميل الكلمات المشبوهة من الملف"""
    spam_keywords = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # تجاهل السطور الفارغة والتعليقات
                line = line.strip()
                if line and not line.startswith('#'):
                    spam_keywords.add(line.lower())
        return spam_keywords
    except FileNotFoundError:
        print(f"خطأ: الملف {file_path} غير موجود")
        return set()

def check_for_spam(email_text, spam_keywords):
    """
    فحص نص البريد الإلكتروني للكشف عن محتوى مشبوه
    Returns:
        - is_spam (bool): هل البريد مشبوه أم لا
        - matched_keywords (list): الكلمات المشبوهة التي تم العثور عليها
        - spam_score (float): درجة احتمالية كون البريد مزعجاً (0-100)
    """
    email_text = email_text.lower()
    matched_keywords = []
    
    # البحث عن الكلمات المشبوهة
    for keyword in spam_keywords:
        if keyword in email_text:
            matched_keywords.append(keyword)
    
    # حساب درجة احتمالية كون البريد مزعجاً
    # كل كلمة مشبوهة تزيد النتيجة بنسبة معينة
    base_score_per_keyword = 15  # كل كلمة تزيد 15 نقطة
    spam_score = min(100, len(matched_keywords) * base_score_per_keyword)
    
    # اعتبار البريد مزعجاً إذا تم العثور على كلمتين مشبوهتين على الأقل
    # أو إذا كانت درجة الخطورة أعلى من 40
    is_spam = len(matched_keywords) >= 2 or spam_score > 40
    
    return {
        'is_spam': is_spam,
        'matched_keywords': matched_keywords,
        'spam_score': spam_score,
        'reasons': [
            f"تم العثور على الكلمة المشبوهة: {keyword}"
            for keyword in matched_keywords
        ]
    }

def analyze_email(email_text):
    """
    تحليل البريد الإلكتروني وإرجاع النتائج
    """
    # تحميل الكلمات المشبوهة
    spam_keywords = load_spam_keywords()
    
    # فحص البريد
    results = check_for_spam(email_text, spam_keywords)
    
    # تحويل درجة الخطورة إلى درجة الأمان (عكس النتيجة)
    safety_score = 100 - results['spam_score']
    
    return {
        'probability': safety_score,  # درجة الأمان
        'is_spam': results['is_spam'],
        'matched_keywords': results['matched_keywords'],
        'reasons': results['reasons']
    } 