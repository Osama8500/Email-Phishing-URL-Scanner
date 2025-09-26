from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify  # Flask web framework
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import numpy as np                        # Numerical operations
import pickle                             # Loading pickle models
import joblib                             # Loading joblib models
import re                                 # Regular expressions
import os, tempfile                       # File system operations
import pandas as pd                       # Data manipulation for PE features
import pefile                             # Parsing PE files
import zipfile, rarfile                   # Handling archives (ZIP, RAR)
import idna
from idna import decode as idna_decode
from urllib.parse import urlparse         # URL parsing
from werkzeug.utils import secure_filename # Secure file naming
from feature import FeatureExtraction     # Custom feature extractor for URLs
from collections import OrderedDict       # Ordered dict for text scan results
from lime.lime_text import LimeTextExplainer  # LIME for text explanations
from PyPDF2 import PdfReader             # PDF file reading
import logging
import time
import hashlib
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import shutil



# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app and database
app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.secret_key = 'your-secret-key-here'  # needed for flash messages

db = SQLAlchemy(app)

# تهيئة Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50))  # 'url', 'email', 'file'
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    content_hash = db.Column(db.String(64))  # Hash of scanned content
    is_threat = db.Column(db.Boolean)
    threat_level = db.Column(db.String(20))  # 'low', 'medium', 'high'
    scan_details = db.Column(db.JSON)
    scan_time = db.Column(db.Float)  # scan duration in seconds
    
    def __repr__(self):
        return f'<ScanResult {self.scan_type} {self.scan_date}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

class Notification(db.Model):
    """نموذج الإشعارات"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default='system')  # system, threat, scan, security
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reference_id = db.Column(db.Integer)  # للإشارة إلى عنصر مرتبط (مثل رسالة دعم فني)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'type': self.type,
            'is_read': self.is_read,
            'created_at': self.created_at,
            'reference_id': self.reference_id
        }

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    support_message_id = db.Column(db.Integer, db.ForeignKey('support_message.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', backref=db.backref('sent_messages', lazy=True))
    support_message = db.relationship('SupportMessage', backref=db.backref('chat_messages', lazy=True, order_by='ChatMessage.created_at'))

class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, in_progress, answered, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('support_messages', lazy=True))
    responses = db.relationship('SupportResponse', backref='message', lazy=True)

class SupportResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('support_message.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    response_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    admin = db.relationship('User', backref=db.backref('support_responses', lazy=True))

# Create database tables
with app.app_context():
    try:
        # إنشاء جميع الجداول إذا لم تكن موجودة
        db.create_all()
        
        # إنشاء مستخدم Osama كمشرف إذا لم يكن موجوداً
        admin_user = User.query.filter_by(username="Osama").first()
        if not admin_user:
            admin_user = User(
                username="Osama",
                email="osama@example.com",
                is_admin=True
            )
            admin_user.set_password("123456")
            db.session.add(admin_user)
            db.session.commit()
            print("تم إنشاء حساب المشرف Osama")
        
        print("تم تهيئة قاعدة البيانات بنجاح!")
    except Exception as e:
        print(f"حدث خطأ أثناء تهيئة قاعدة البيانات: {str(e)}")
        import traceback
        print(traceback.format_exc())

print("Loading models...")
try:
    logger.info("Loading URL model...")
    with open('newmodel.pkl', 'rb') as f:
        url_model = pickle.load(f)           # URL phishing detection model
    logger.info("URL model loaded successfully")
    
    logger.info("Loading message model and vectorizer...")
    msg_model = joblib.load('spam_model.pkl')
    vectorizer = joblib.load('vector.pkl')
    logger.info("Message model and vectorizer loaded successfully")
    
    logger.info("Loading PE model...")
    pe_model = joblib.load('malware_model.pkl')  # PE malware detection model
    
    logger.info("All models loaded successfully!")
except Exception as e:
    logger.error(f"Error loading models: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())

# Regex: capture URLs, including Unicode domains
url_pattern = re.compile(r'(https?://[^\s]+|www\.[^\s]+)', re.UNICODE)

# تحديث الأنماط المشبوهة لتشمل المزيد من الحالات
MALICIOUS_PATTERNS = {
    'bitcoin_address': (
        r'(?:^|\s|[^a-zA-Z0-9])(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[0-9A-Za-z]{25,39})(?:$|\s|[^a-zA-Z0-9])',
        'عناوين بيتكوين محتملة'
    ),
    'malicious_url': (
        r'(?:https?://|www\.)?(?:[^\s/]+\.)*(?:malware|virus|exploit|hack|crack|keygen|warez|spyware|trojan|ransom)(?:[^\s/]*)\.[a-z]{2,}(?:/[^\s]*)?',
        'روابط قد تكون ضارة'
    ),
    'shell_commands': (
        r'(?:^|\s|[`\'"])(wget\s+|curl\s+|chmod\s+[0-7]{3,4}\s+|rm\s+-rf\s+/?|(?:/usr)?/bin/(?:bash|sh)\s+-[ic]|eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\().*?(?:$|[`\'"])',
        'أوامر شيل قد تكون خطيرة'
    ),
    'sql_injection': (
        r'(?i)(?:\'|\%27)?\s*(?:OR|AND)\s*[\'"]\s*(?:1|0)\s*[\'"]|(?:UNION\s+ALL\s+SELECT|INSERT\s+INTO|UPDATE\s+.*?SET|DELETE\s+FROM|DROP\s+TABLE)\s',
        'محاولات SQL Injection محتملة'
    ),
    'xss_attempts': (
        r'(?i)(?:<script[^>]*>.*?</script>|javascript:|\bon(?:error|load|click|mouseover|submit)\s*=|<img[^>]+src[^>]*=|alert\s*\(|document\.cookie)',
        'محاولات XSS محتملة'
    ),
    'sensitive_data': (
        r'(?i)(?:password|pwd|pass|username|user|admin|root|login|auth|key|token|secret|credentials?|api_?key)\s*[=:]\s*[\'"]((?!\s*[{<%])[^\'"\s]+)[\'"]',
        'بيانات قد تكون حساسة'
    ),
    'ip_addresses': (
        r'(?:^|\s|[^\w.])((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?:$|\s|[^\w.])',
        'عناوين IP - قد تكون مشروعة'
    ),
    'base64_data': (
        r'(?:[A-Za-z0-9+/]{100,}={0,3}(?:\s|$)|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})',
        'بيانات مشفرة Base64 أو JWT tokens'
    ),
    'email_addresses': (
        r'(?i)(?:^|\s|[^\w@.])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Z]{2,}(?:$|\s|[^\w@.])',
        'عناوين بريد إلكتروني - قد تكون مشروعة'
    ),
    'suspicious_paths': (
        r'(?:^|\s|[\'"/])/(?:etc/(?:passwd|shadow|group|gshadow)|proc/self/[a-z]+|sys/[a-z]+/|root/|var/log/|tmp/[^/]+\.(?:php|exe|sh|pl)|Windows/System32/)(?:$|\s|[\'"])',
        'مسارات نظام حساسة'
    ),
    'obfuscated_js': (
        r'(?:eval|setTimeout|setInterval|Function)\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(',
        'جافا سكريبت مموه محتمل'
    ),
    'command_injection': (
        r'(?:[;&|`]\s*(?:cat|wget|curl|nc|ncat|bash|python|perl|ruby|php)\s+|>\s*/dev/null\s+2>&1)',
        'محاولات حقن أوامر محتملة'
    )
}

# تهيئة النماذج
try:
    logger.info("Loading URL model...")
    with open('newmodel.pkl', 'rb') as f:
        url_model = pickle.load(f)
    logger.info("URL model loaded successfully")
except Exception as e:
    logger.error(f"Error loading URL model: {str(e)}")
    logger.error(traceback.format_exc())
    url_model = None

# إضافة متغير عام للتحقق من تهيئة النماذج
_models_checked = False

@app.before_request
def check_models():
    """التحقق من تحميل النماذج قبل معالجة أي طلب"""
    global _models_checked
    if not _models_checked:
        if url_model is None:
            logger.error("URL model not loaded - URL scanning will not work!")
            flash("تحذير: نموذج فحص الروابط غير متوفر. بعض الوظائف قد لا تعمل.", "warning")
        _models_checked = True

def analyze_url_details(url):
    """تحليل تفصيلي للرابط وإرجاع أسباب الخطورة"""
    details = []
    score = 0.0
    total_checks = 0
    
    try:
        # تحليل الرابط
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # قائمة النطاقات العلوية المشبوهة
        suspicious_tlds = {'ru', 'cn', 'tk', 'xyz', 'info', 'top', 'gq', 'ml', 'cf', 'pw'}
        
        # قائمة النطاقات الموثوقة (كما هي)
        trusted_domains = {
            # مواقع التواصل الاجتماعي
            'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'youtube.com',
            'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'whatsapp.com',
            
            # محركات البحث
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com',
            
            # منصات التجارة الإلكترونية
            'amazon.com', 'ebay.com', 'walmart.com', 'aliexpress.com', 'shopify.com',
            'noon.com', 'jumia.com', 'souq.com',
            
            # شركات التكنولوجيا الكبرى
             'apple.com', 'ibm.com', 'oracle.com', 'intel.com',
            'amd.com', 'nvidia.com', 'cisco.com', 'dell.com', 
            
            # منصات التعليم
            'udemy.com', 'coursera.org', 'edx.org', 'duolingo.com', 'khan-academy.org',
            
            # خدمات البريد الإلكتروني
            'gmail.com', 'outlook.com', 'hotmail.com', 'protonmail.com', 'yahoo.com',
            
            # منصات استضافة وتطوير
            'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 
            'azure.microsoft.com', 'cloud.google.com', 'heroku.com', 'digitalocean.com',
            
            # خدمات الترفيه
             'spotify.com', 'disney.com', 'hulu.com', 'twitch.tv',
            'steam.com', 'ea.com', 'playstation.com', 'xbox.com',
            
    
            
            # خدمات الاتصال والمؤتمرات
            'zoom.us',  'meet.google.com', 'skype.com', 'discord.com',
            
            # خدمات التخزين السحابي
            'dropbox.com', 'drive.google.com', 'onedrive.live.com', 'icloud.com', 'box.com',
            
            # منصات الدفع
            'paypal.com', 'stripe.com', 'visa.com', 'mastercard.com', 'americanexpress.com',
            
            # مواقع حكومية وتعليمية
            'edu', 'gov', 'mil', 'int',
         
        }

        # فحص النطاقات الموثوقة
        domain_parts = domain.split('.')
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else domain
        
         # التحقق من النطاق الرئيسي والنطاقات الفرعية للمواقع الموثوقة
        if any(base_domain.endswith(trusted) for trusted in trusted_domains):
            return [], 0.0  # إرجاع قائمة فارغة ودرجة خطورة 0 للنطاقات الموثوقة

        # فحص النطاق العلوي
        total_checks += 1
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in suspicious_tlds:
            details.append(f"نطاق علوي مشبوه (.{tld})")
            score += 25.5

        # فحص الكلمات المشبوهة في الرابط
        suspicious_words = {
            'login': 'صفحة تسجيل دخول مقلدة',
            'account': 'صفحة حساب مقلدة',
            'verify': 'صفحة تحقق مشبوهة',
            'secure': 'ادعاء كاذب بالأمان',
            'banking': 'تقليد خدمات بنكية',
            'update': 'طلب تحديث مشبوه',
            'password': 'محاولة سرقة كلمة المرور',
            'hack': 'محتوى ضار',
            'crack': 'برامج قرصنة',
            'keygen': 'مولد مفاتيح غير قانوني',
            'warez': 'برامج مقرصنة',
            'torrent': 'مشاركة ملفات غير قانونية'
        }

        # فحص الكلمات المشبوهة في المسار والاستعلام
        total_checks += 1
        suspicious_word_found = False
        for word, reason in suspicious_words.items():
            if word in path or word in query:  # تجاهل الكلمات في اسم النطاق
                details.append(reason)
                suspicious_word_found = True
        if suspicious_word_found:
            score += 20.5

        

        # فحص تشفير/إخفاء الرابط
        total_checks += 1
        if 'bit.ly' in domain or 'tinyurl' in domain or 'goo.gl' in domain:
            details.append("رابط مختصر مشبوه")
            score += 15.5

        # فحص نسبة الأحرف الخاصة
        total_checks += 1
        special_chars = re.findall(r'[^a-zA-Z0-9\-\.]', domain)
        special_char_ratio = len(special_chars) / len(domain) if domain else 0
        if special_char_ratio > 0.2:
            details.append("نسبة عالية من الأحرف الخاصة في النطاق")
            score += 20.5

        # فحص طول النطاق
        total_checks += 1
        if len(domain) > 30:
            details.append("طول النطاق مشبوه")
            score += 10.5

        # فحص بروتوكول الأمان
        total_checks += 1
        if not url.startswith('https://'):
            if url.startswith('http://'):
                details.append("بروتوكول HTTP غير آمن: البيانات المرسلة غير مشفرة ويمكن اعتراضها. يُفضل استخدام HTTPS للحماية والتشفير.")
            else:
                details.append("بروتوكول غير معروف أو غير آمن: يجب استخدام HTTPS لضمان تشفير البيانات وحماية المعلومات الحساسة.")
            score += 10.5

        # تعديل النتيجة النهائية بناءً على عدد الفحوصات
        if total_checks > 0:
            # تطبيع النتيجة لتكون بين 0 و 100
            normalized_score = (score / (total_checks * 30)) * 100
            final_score = min(max(normalized_score, 0.0), 100.0)
            return details, round(final_score, 2)

    except Exception as e:
        details.append(f"خطأ في تحليل الرابط: {str(e)}")
        return details, 50.0

    return details, 0.0

def scan_url(url):
    """فحص رابط واحد للتحقق من كونه مشبوه"""
    start_time = time.time()
    details, risk_score = analyze_url_details(url)
    
    # إضافة فحص الهوموغراف إلى التحليل اليدوي
    homograph_alert = check_homograph_tld(url)
    if homograph_alert:
        details.append(homograph_alert)
        risk_score = min(risk_score + 40, 100)  # زيادة درجة الخطورة مع ضمان ألا تتجاوز 100%
    
    # إنشاء إشعار للمستخدم عند اكتشاف تهديد فقط إذا كانت النتيجة مشبوهة
    if 'user_id' in session and risk_score > 50:
        username = User.query.get(session['user_id']).username
        create_admin_notification(
            title=f"عملية فحص رابط جديدة",
            message=f"قام المستخدم {username} بفحص الرابط: {url}\nالنتيجة: مشبوه\nدرجة الخطورة: {risk_score}%",
            type="scan"
        )
    
    if not details:  # إذا لم يتم العثور على أي مشاكل في التحليل اليدوي
        try:
            feats = FeatureExtraction(url).getFeaturesList()
            n = url_model.n_features_in_
            feats = (feats + [0]*n)[:n]
            x = np.array(feats).reshape(1, n)
            pred = url_model.predict(x)[0]
            proba = url_model.predict_proba(x)[0]
            
            if pred == 1:  # إذا صنف النموذج الرابط كآمن
                safety_score = float(proba[1] * 100)  # استخدام احتمالية النموذج
                result = {
                    'url': url,
                    'status': 'safe',
                    'reason': 'تم التحقق من أمان الرابط',
                    'probability': round(safety_score, 2),
                    'details': ['الرابط آمن وموثوق']
                }
                # تخزين النتيجة في قاعدة البيانات
                scan_time = time.time() - start_time
                scan_result = ScanResult(
                    scan_type='url',
                    content_hash=hashlib.sha256(url.encode()).hexdigest(),
                    is_threat=False,
                    threat_level='low',
                    scan_details=result,
                    scan_time=scan_time
                )
                db.session.add(scan_result)
                db.session.commit()
                return result
        except Exception as e:
            logger.error(f"Error in ML prediction: {str(e)}")

    # إذا كان هناك مشاكل في التحليل اليدوي أو فشل التحقق الآلي
    result = {
        'url': url,
        'status': 'malicious',
        'reason': details[0] if details else 'تم اكتشاف مخاطر محتملة',
        'probability': round(risk_score, 2),
        'details': details if details else ['تم اكتشاف أنماط مشبوهة في الرابط']
    }
    
    # تخزين النتيجة في قاعدة البيانات
    scan_time = time.time() - start_time
    scan_result = ScanResult(
        scan_type='url',
        content_hash=hashlib.sha256(url.encode()).hexdigest(),
        is_threat=True,
        threat_level='high' if risk_score > 75 else 'medium' if risk_score > 50 else 'low',
        scan_details=result,
        scan_time=scan_time
    )
    db.session.add(scan_result)
    db.session.commit()
    
    return result

def check_models_loaded():
    """التحقق من تحميل النماذج"""
    if msg_model is None or vectorizer is None:
        raise RuntimeError("نماذج فحص البريد الإلكتروني غير محملة")

# Helper to extract non-ASCII characters in a URL
def get_non_standard_chars(url):
    return sorted(set(ch for ch in url if ord(ch) > 127))


def scan_email(content):
    """Scan email content with database storage, including homograph URL detection"""
    try:
        # قائمة الروابط الهوموقرافية مضمّنة مباشرة داخل الدالة
        HOMO_URLS = [
            "https://www.аррӏе.com","https://www.gооglе.com","https://www.fасеbооk.com","https://www.yоutube.com","https://www.micrоsоft.com", "https://www.twittеr.com",
            "https://www.linkedіn.com", "https://www.ebаy.com","https://www.wikipеdia.org", "https://www.reddіt.com", "https://www.instagrаm.com", "https://www.paypаl.com",
            "https://www.adоbe.com", "https://www.whatsаpp.com", "https://www.telegram.mе","https://www.slack.cоm", "https://www.twitch.tѵ", "https://www.spotіfy.com",
            "https://www.yahоо.com","https://www.hоtmail.com","https://www.bing.cоm", "https://www.airbnb.cоm", "https://www.uber.cоm", "https://www.teslа.com",
            "https://www.samsung.cоm", "https://www.sony.cоm", "https://www.apple.сom", "https://www.googlе.com", "https://www.facebоok.com", "https://www.alibаba.com",
            "https://www.skype.cоm","https://www.githuЬ.com", "https://www.stackоverflow.com", "https://www.medium.cоm","https://www.quоra.com",
            "https://www.gооgle.com","https://www.аdоbе.com","https://www.mісrоsоft.com","https://www.рayраl.com","https://www.tesӏa.com","https://www.ebау.com",
            "https://www.сisсo.com", "https://www.νisa.com", "https://www.gοοgle.com", "https://www.wikipediа.org", "https://www.lіnkedin.com", "https://www.twіtter.com",
            "https://www.ԁell.com""https://www.cnпn.com","https://www.bвc.com","https://www.pіnterest.com",
            "https://www.dropbох.com","https://www.payраl.com","https://www.shoрify.com","https://www.mailchіmp.com","https://www.spotіfy.com","https://www.reutеrs.com",
            "https://www.lіve.com","https://www.blooмberg.com","https://www.forЬes.com","https://www.huffіngtonpost.com","https://www.tеd.com","https://www.medіum.com",
            "https://www.aіrchina.com", "https://www.drорbox.com", "https://www.wordprеss.com", "https://www.adіdas.com", "https://www.wеllsfargo.com", 
            "https://www.chаse.com", "https://www.aтt.com", "https://www.verіzon.com",   "https://www.tіktok.com", 
            "https://www.transfеrwise.com","https://www.bаnkofamerica.com","https://www.snарchat.com", "https://www.aіrtel.com", 
            "https://www.esрn.com", "https://www.weаther.com", "https://www.craigslіst.org", "https://www.indеed.com", "https://www.glassdoоr.com",
            "https://www.zіllow.com", 
        ]

        check_models_loaded()
        start_time = time.time()
        reasons = []
        safety_score = 100.0
        url_safety_score = 100.0
        homograph_found = False

        # 0. فحص كلمة "spam" المباشرة
        if 'spam' in content.lower():
            safety_score -= 10
            reasons.append("كلمة 'spam' مكتشفة: -10% من درجة الأمان")

        # 1. فحص الكلمات المشبوهة
        kws = check_spam_keywords(content)
        if kws:
            penalty = min(len(kws) * 10, 30)
            safety_score -= penalty
            reasons.append(f"تم اكتشاف كلمات مشبوهة: {', '.join(kws)} (-{penalty}% من درجة الأمان)")

        # 2. تصنيف النص
        clean = remove_urls(content)
        vec = vectorizer.transform([clean])
        txt_pred = msg_model.predict(vec)[0]
        txt_proba = msg_model.predict_proba(vec)[0]
        # استخدام درجة الأمان بدلاً من نص التصنيف
        proba_safe = txt_proba[0] * 100
        if txt_pred == 0:
            reasons.append(f"نموذج التصنيف: آمن (ثقة {proba_safe:.0f}%) بدون خصم)")
        else:
            proba_spam = txt_proba[1] * 100
            deduction = min(proba_spam * 0.5, 30)
            safety_score -= deduction
            reasons.append(f"نموذج التصنيف: مشبوه (ثقة {proba_spam:.0f}%) (-{deduction:.0f}% من درجة الأمان)")

        # 3. تحليل LIME
        explanations = explain_email(clean)  # يفترض استخدام مكتبة LIME هنا
        if explanations:
            reasons.append("تفاصيل تحليل LIME وتعديل درجة الأمان:")
            for feat, weight in explanations:
                pct = weight * 100
                if pct > 0:
                    safety_score += pct
                    reasons.append(f"+{pct:.0f}% لدرجة الأمان بسبب '{feat}'")
                else:
                    safety_score -= abs(pct)
                    reasons.append(f"-{abs(pct):.0f}% لدرجة الأمان بسبب '{feat}'")

        # 4. الكشف عن روابط هوموقرافية
        for homo_url in HOMO_URLS:
            if homo_url in content:
                homograph_found = True
                non_std = get_non_standard_chars(homo_url)
                reasons.append(
                    f"رابط هوموقرافي مكتشف: {homo_url} → أحرف غير قياسية: {', '.join(non_std)}"
                )

        # 5. فحص الروابط العادية وتحليلها
        urls = extract_urls(content)
        url_results = []
        if urls:
            bad = 0
            probs = []
            for u in urls:
                res = scan_url(u)
                homo = check_homograph_tld(u)
                res['homograph'] = homo
                url_results.append(res)

                if homo:
                    homograph_found = True
                    non_std = get_non_standard_chars(u)
                    reasons.append(
                        f"تحذير هوموقراف من خلال TLD: {u} → أحرف غير قياسية: {', '.join(non_std)}"
                    )

                if res['status'] == 'malicious':
                    bad += 1
                    reasons.append(f"رابط مشبوه: {u} ({res['reason']})")
                probs.append(res['probability'])
            url_safety_score = sum(probs) / len(probs)
            if bad > 0:
                penalty = (bad / len(urls)) * 30
                safety_score = max(safety_score - penalty, 30)
                reasons.append(f"خصم إضافي {penalty:.0f}% لوجود {bad}/{len(urls)} روابط مشبوهة")

        # 6. تطبيق نقص الثقة عند وجود هوموقراف (50%)
        if homograph_found:
            reasons.append
            safety_score *= 0.7
            url_safety_score *= 0.3

        # 7. احتساب النتيجة النهائية
        safety_score = max(0, min(safety_score, 100))
        final_score = max(0, min(safety_score * 0.7 + url_safety_score * 0.3, 100))
        final = 'Ham' if final_score >= 50 else 'Spam'
        scan_time = time.time() - start_time

        result = {
            'status': final,
            'probability': round(final_score, 2),  # هذه هي درجة الأمان الظاهرة
            'reasons': reasons,
            'url_results': url_results
        }


        # تخزين
        scan_result = ScanResult(
            scan_type='email',
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
            is_threat=(final == 'Spam'),
            threat_level=('high' if final_score < 25 else 'medium' if final_score < 60 else 'low'),
            scan_details=result,
            scan_time=scan_time
        )
        db.session.add(scan_result)
        db.session.commit()

        # إشعارات
        if 'user_id' in session and final == 'Spam':
            create_notification(
                user_id=session['user_id'],
                title='تحذير: بريد مشبوه',
                message=f'تم اكتشاف بريد مشبوه (ثقة {final_score:.0f}%)',
                type='threat'
            )
            username = User.query.get(session['user_id']).username
            create_admin_notification(
                title='فحص بريد إلكتروني',
                message=f'المستخدم {username} فحص بريداً → {final} ({final_score:.0f}%)',
                type='scan'
            )

        return result
    except Exception as e:
        logger.error(f"Error scanning email: {e}")
        return {'status':'error','probability':0,'reasons':[f'خطأ: {e}'],'url_results':[]}

def check_homograph_tld(url):
    """الكشف عن الهوموغراف باستخدام Punycode أو أحرف يونيكود مشابهة"""
    domain = urlparse(url).netloc
    try:
        decoded_domain = idna.decode(domain)
    except idna.IDNAError:
        decoded_domain = domain
    if 'xn--' in domain or 'xn--' in decoded_domain:
        return 'تم اكتشاف هوموقراف Punycode'
    if any(ord(c) > 0x7F for c in decoded_domain):
        return 'تم اكتشاف أحرف غير ASCII (هوموغراف محتمل)'
    tld = decoded_domain.split('.')[-1]
    if len(tld) > 3:
        return f'رابط هوموقرافي.{tld}'
    return None


def load_spam_keywords(file_path='spam_keywords.txt'):
    """تحميل الكلمات المشبوهة من الملف"""
    keywords = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    keywords.add(line.lower())
        return keywords
    except FileNotFoundError:
        print(f"خطأ: الملف {file_path} غير موجود")
        return set()

# تحميل الكلمات المشبوهة من الملف
spam_keywords = load_spam_keywords()

# ------------------ Helper Functions ------------------ #

def check_homograph_tld(url):
    """الكشف عن الهوموغراف باستخدام Punycode أو أحرف يونيكود مشابهة"""
    domain = urlparse(url).netloc
    
    try:
        decoded_domain = idna.decode(domain)
    except idna.IDNAError:
        decoded_domain = domain
    
    # الكشف عن Punycode
    if 'xn--' in domain or 'xn--' in decoded_domain:
        return 'تم اكتشاف هوموغراف Punycode'
    
    # الكشف عن أحرف غير ASCII (مثل الكيريلية)
    if any(ord(char) > 0x7F for char in decoded_domain):
        return 'تم اكتشاف أحرف غير ASCII (هوموغراف محتمل)'
    
    # التحقق من طول النطاق العلوي (TLD)
    tld = decoded_domain.split('.')[-1]
    if len(tld) > 3:
        return f'رابط هوموقرافي.{tld}'
    
    return None

def extract_urls(text):
    """استخراج الروابط من النص مع دعم أفضل"""
    # نمط محسن للعثور على الروابط
    url_pattern = re.compile(
        r'(?:(?:https?://)|(?:www\.))(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)
    # تنظيف وتصحيح الروابط
    cleaned_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        cleaned_urls.append(url)
    return cleaned_urls

def remove_urls(text):
    """Remove URLs from text to avoid them affecting text classification"""
    return url_pattern.sub('', text)

def check_spam_keywords(text):
    """Detect presence of known spam trigger keywords"""
    found = []
    lower = text.lower()
    for kw in spam_keywords:
        if kw in lower:
            found.append(kw)
    return found

def explain_email(text):
    """Generate LIME explanations for email text classification"""
    explainer = LimeTextExplainer(class_names=['Ham', 'Spam'])
    def pred_prob(texts):
        vecs = vectorizer.transform(texts)
        return msg_model.predict_proba(vecs)
    exp = explainer.explain_instance(text, pred_prob, num_features=5)
    return exp.as_list()


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('يرجى تسجيل الدخول للوصول إلى هذه الصفحة', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('يرجى تسجيل الدخول للوصول إلى هذه الصفحة', 'warning')
            return redirect(url_for('login', next=request.url))
        
        user = User.query.get(session['user_id'])
        if not user:
            session.pop('user_id', None)
            session.pop('is_admin', None)
            flash('يرجى تسجيل الدخول مرة أخرى', 'warning')
            return redirect(url_for('login', next=request.url))
            
        if not user.is_admin:
            flash('غير مصرح لك بالوصول إلى هذه الصفحة', 'error')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/url_check', methods=['GET', 'POST'])
def url_check():
    """صفحة فحص الروابط"""
    if request.method == 'POST':
        url = request.form.get('url_text')
        if not url:
            flash('الرجاء إدخال رابط للفحص', 'error')
            return render_template('url.html')
            
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            result = scan_url(url)
            result['scan_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # إنشاء إشعار للمستخدم إذا كان مسجل دخول
            if 'user_id' in session and result['status'] == 'malicious':
                create_notification(
                    user_id=session['user_id'],
                    title=f'نتيجة فحص الرابط: مشبوه',
                    message=f'تم فحص الرابط: {url}\nالنتيجة: مشبوه\nدرجة الخطورة: {result["probability"]}%',
                    type='scan'
                )
            
            return render_template('url.html', url_res=result)
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            flash(f'حدث خطأ أثناء فحص الرابط: {str(e)}', 'error')
            return render_template('url.html')
            
    return render_template('url.html')

@app.route('/email_check', methods=['GET', 'POST'])
def email_check():
    """صفحة فحص البريد الإلكتروني"""
    session.pop('_flashes', None)
    
    email_res = None
    if request.method == 'POST':
        content = request.form.get('text')
        if content:
            try:
                result = scan_email(content)
                
                email_res = {
                    'content': content,
                    'status': result['status'],
                    'probability': result['probability'],
                    'reasons': result['reasons'],
                    'url_results': result['url_results'],
                    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # إنشاء إشعار للمستخدم إذا كان مسجل دخول
                if 'user_id' in session:
                    status = 'مشبوه' if result['status'] == 'Spam' else 'آمن'
                    create_notification(
                        user_id=session['user_id'],
                        title=f'نتيجة فحص البريد: {status}',
                        message=f'تم فحص البريد الإلكتروني\nالنتيجة: {status}\nدرجة الثقة: {result["probability"]}%',
                        type='scan'
                    )
                    
                    # إنشاء إشعار للمشرفين
                    username = User.query.get(session['user_id']).username
                    create_admin_notification(
                        title=f"عملية فحص بريد إلكتروني جديدة",
                        message=f"قام المستخدم {username} بفحص بريد إلكتروني\nالنتيجة: {status}\nدرجة الثقة: {result['probability']}%",
                        type="scan"
                    )
                
            except Exception as e:
                flash(f'حدث خطأ أثناء فحص البريد: {str(e)}', 'error')
        else:
            flash('الرجاء إدخال نص البريد الإلكتروني', 'error')
    
    return render_template('email.html', email_res=email_res)


def extract_archive(filepath, extract_dir=None):
    if extract_dir is None:
        extract_dir = os.path.join("extracted", os.path.splitext(os.path.basename(filepath))[0])
    os.makedirs(extract_dir, exist_ok=True)

    try:
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath, 'r') as z:
                z.extractall(extract_dir)
            return True
        elif rarfile.is_rarfile(filepath):
            with rarfile.RarFile(filepath, 'r') as r:
                r.extractall(extract_dir)
            return True
        return False
    except Exception:
        return False
# دالة مساعدة لحساب الهاش
def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# دالة فحص الملفات النصية المحدثة
def scan_text_file(filepath):
    results = OrderedDict()
    danger_score = 0
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read()
        
        for pid, (pat, desc) in MALICIOUS_PATTERNS.items():
            matches = re.findall(pat, data, flags=re.IGNORECASE)
            if matches:
                results[pid] = {
                    'description': desc,
                    'count': len(matches),
                    'examples': list(set(matches))[:3]
                }
                danger_score += len(matches) * 10
                
    danger_score = min(danger_score, 100)
    return results, danger_score


def extract_pe_features(filepath):
    """Extract numeric and directory features from a PE file"""
    pe = pefile.PE(filepath)
    # Count suspicious patterns in raw data
    data = open(filepath, 'rb').read().decode('latin-1', errors='ignore')
    bitcoin_count = len(re.findall(MALICIOUS_PATTERNS['bitcoin_address'][0], data))
    # Collect selected PE header fields
    features = {
        'Machine': pe.FILE_HEADER.Machine,
        'DebugSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size,
        'DebugRVA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress,
        'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
        'MajorOSVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
        'ExportRVA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
        'ExportSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
        'IatVRA': pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
        'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
        'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
        'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
        'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
        'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
        'ResourceSize': pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
        'BitcoinAddresses': bitcoin_count
    }
    pe.close()
    # Align DataFrame to model features
    df = pd.DataFrame([features])
    for col in pe_model.feature_names_in_:
        if col not in df.columns:
            df[col] = 0
    df = df[pe_model.feature_names_in_]
    return df



# دالة فحص الملفات المستخرجة المحدثة
def scan_extracted_files(extract_dir):
    results = []
    for root, _, files in os.walk(extract_dir):
        for file in files:
            path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            file_hash = calculate_hash(path)
            
            result = {
                'filename': file,
                'file_type': 'Unknown',
                'hash_sha256': file_hash,
                'label': 'آمن',
                'probability': 0,
                'details': {},
                'nested_results': []
            }

            if ext in ('.exe', '.dll'):
                features = extract_pe_features(path)
                if features is not None:
                    pred = pe_model.predict(features)[0]
                    proba = pe_model.predict_proba(features)[0]
                    result.update({
                        'file_type': 'PE File',
                        'label': 'آمن' if pred == 1 else 'ضار',
                        'probability': round(max(proba) * 100, 2),
                        'details': features.to_dict()
                    })
                    
            elif ext == '.txt':
                text_results, danger_score = scan_text_file(path)
                result.update({
                    'file_type': 'Text File',
                    'label': 'مشبوه' if danger_score > 50 else 'آمن',
                    'probability': danger_score,
                    'details': text_results
                })
                
            elif ext in ('.zip', '.rar'):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    if extract_archive(path, tmp_dir):
                        nested_results = scan_extracted_files(tmp_dir)
                        max_prob = max([r['probability'] for r in nested_results], default=0)
                        result.update({
                            'file_type': 'Archive',
                            'label': 'مشبوه' if max_prob > 50 else 'آمن',
                            'probability': max_prob,
                            'nested_results': nested_results
                        })
            
            results.append(result)
    return results
# تعديل نقطة النهاية الرئيسية
@app.route('/file_check', methods=['GET', 'POST'])
def file_check():
    if request.method == 'POST':
        if 'pe_file' not in request.files:
            return jsonify({'error': 'لم يتم اختيار ملف'}), 400
            
        file = request.files['pe_file']
        if file.filename == '':
            return jsonify({'error': 'اسم ملف غير صالح'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            file_hash = calculate_hash(filepath)
            ext = os.path.splitext(filename)[1].lower()
            
            result = {
                'filename': filename,
                'file_type': 'Unknown',
                'hash_sha256': file_hash,
                'label': 'آمن',
                'probability': 0,
                'details': {},
                'nested_results': []
            }

            if ext in ('.zip', '.rar'):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    if extract_archive(filepath, tmp_dir):
                        nested_results = scan_extracted_files(tmp_dir)
                        max_prob = max([r['probability'] for r in nested_results], default=0)
                        result.update({
                            'file_type': 'Archive',
                            'label': 'مشبوه' if max_prob > 50 else 'آمن',
                            'probability': max_prob,
                            'nested_results': nested_results
                        })
                        
            elif ext == '.txt':
                text_results, danger_score = scan_text_file(filepath)
                result.update({
                    'file_type': 'Text File',
                    'label': 'مشبوه' if danger_score > 50 else 'آمن',
                    'probability': danger_score,
                    'details': text_results
                })
                
            else:
                features = extract_pe_features(filepath)
                if features is not None:
                    pred = pe_model.predict(features)[0]
                    proba = pe_model.predict_proba(features)[0]
                    result.update({
                        'file_type': 'PE File',
                        'label': 'آمن' if pred == 1 else 'ضار',
                        'probability': round(max(proba) * 100, 2),
                        'details': features.to_dict()
                    })

            os.remove(filepath)
            return jsonify({
                'success': True,
                'result': result,
                'recommendations': [
                    'حذف الملفات المصابة',
                    'تحديث برامج الحماية'
                ]
            })
            
        except Exception as e:
            os.remove(filepath)
            return jsonify({'error': f'حدث خطأ: {str(e)}'}), 500

    return render_template('file.html')


def scan_text_content(content):
    """تحليل محتوى النص وإرجاع النتائج"""
    results = {
        'patterns_found': {},
        'suspicious_urls': [],
        'danger_score': 0,
        'details': []
    }
    
    # استخراج وفحص الروابط
    urls = list(set(extract_urls(content)))[:10]  # نفحص أول 10 روابط فقط
    
    # فحص الروابط بشكل متوازي
    suspicious_count = 0
    for url in urls:
        try:
            url_result = scan_url(url)
            if url_result['status'] == 'malicious':
                suspicious_count += 1
                results['suspicious_urls'].append({
                    'url': url,
                    'reason': url_result['reason'],
                    'details': url_result['details']
                })
                results['details'].append(f"رابط مشبوه: {url}")
                for detail in url_result['details']:
                    results['details'].append(f"- {detail}")
        except:
            continue
    
    # تحديث درجة الخطورة بناءً على عدد الروابط المشبوهة
    if suspicious_count > 0:
        results['danger_score'] += min(suspicious_count * 20, 60)
    
    # فحص الأنماط المشبوهة
    for pid, (pattern, desc) in MALICIOUS_PATTERNS.items():
        try:
            matches = re.findall(pattern, content, flags=re.IGNORECASE)
            if matches:
                unique_matches = list(set(matches))
                results['patterns_found'][pid] = {
                    'description': desc,
                    'count': len(matches),
                    'examples': unique_matches[:3]
                }
                results['danger_score'] += min(len(matches) * 15, 40)
                results['details'].append(f"تم اكتشاف {desc} ({len(matches)} مرات)")
                
                # التوقف إذا وجدنا تهديدات كافية
                if results['danger_score'] >= 80:
                    break
        except:
            continue
    
    results['danger_score'] = min(100, results['danger_score'])
    return results

def scan_pdf_file(filepath):
    """فحص ملفات PDF للبحث عن المحتوى المشبوه"""
    results = {
        'patterns_found': {},
        'suspicious_urls': [],
        'danger_score': 0,
        'details': []
    }
    
    try:
        # فتح ملف PDF وقراءة أول 15 صفحات فقط
        reader = PdfReader(filepath)
        content = ""
        
        pages_to_scan = min(15, len(reader.pages))
        for i in range(pages_to_scan):
            try:
                page_text = reader.pages[i].extract_text()
                if page_text:
                    content += page_text + "\n"
            except:
                continue
        
        if content:
            # استخدام الفحص المحسن للنص
            text_results = scan_text_content(content)
            results.update(text_results)
            
            if pages_to_scan < len(reader.pages):
                results['details'].append(f"تم فحص {pages_to_scan} صفحات من أصل {len(reader.pages)}")
    
    except Exception as e:
        results['details'].append("خطأ في قراءة ملف PDF")
        results['danger_score'] = 50
    
    return results

@app.route('/reports/summary')
def analysis_summary():
    """عرض ملخص التحليلات باستخدام البيانات الفعلية"""
    # إحصائيات عامة
    total_scans = ScanResult.query.count()
    detected_threats = ScanResult.query.filter_by(is_threat=True).count()
    safe_items = total_scans - detected_threats
    
    # متوسط وقت الفحص
    avg_scan_time = db.session.query(func.avg(ScanResult.scan_time)).scalar() or 0
    
    # آخر التحليلات
    recent_analyses = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(10).all()
    
    analyses_list = []
    for analysis in recent_analyses:
        analyses_list.append({
            'type': {
                'url': 'فحص رابط',
                'email': 'فحص بريد',
                'file': 'فحص ملف'
            }.get(analysis.scan_type, 'غير معروف'),
            'date': analysis.scan_date.strftime('%Y-%m-%d %H:%M'),
            'result': 'تم اكتشاف تهديد' if analysis.is_threat else 'آمن',
            'severity': analysis.threat_level
        })
    
    data = {
        'total_scans': total_scans,
        'detected_threats': detected_threats,
        'safe_items': safe_items,
        'avg_scan_time': round(avg_scan_time, 3),
        'recent_analyses': analyses_list
    }
    
    return render_template('analysis_summary.html', **data)

@app.route('/reports/threats')
def detected_threats():
    """عرض التهديدات المكتشفة باستخدام البيانات الفعلية"""
    # استرجاع آخر 50 تهديد
    threat_results = ScanResult.query.filter_by(is_threat=True).order_by(ScanResult.scan_date.desc()).limit(50).all()
    
    threats = []
    for result in threat_results:
        details = result.scan_details
        
        if result.scan_type == 'url':
            name = 'محاولة تصيد احتيالي'
            description = details.get('reason', 'رابط مشبوه')
            icon = 'fish'
        elif result.scan_type == 'email':
            name = 'بريد مشبوه'
            description = details.get('reasons', ['بريد غير آمن'])[0]
            icon = 'envelope'
        else:  # file
            name = 'ملف ضار'
            description = details.get('details', ['ملف مشبوه'])[0]
            icon = 'file'
        
        threats.append({
            'name': name,
            'description': description,
            'type': result.scan_type,
            'icon': icon,
            'date': result.scan_date.strftime('%Y-%m-%d %H:%M'),
            'source': {
                'url': 'فحص الروابط',
                'email': 'فحص البريد',
                'file': 'فحص الملفات'
            }.get(result.scan_type, 'غير معروف'),
            'severity': result.threat_level
        })
    
    return render_template('detected_threats.html', threats=threats)

@app.route('/reports/statistics')
def scan_statistics():
    """عرض إحصائيات الفحص باستخدام البيانات الفعلية"""
    # إحصائيات عامة لكل نوع فحص
    stats_by_type = {}
    scan_types = ['url', 'email', 'file']
    
    for scan_type in scan_types:
        # استعلام البيانات لهذا النوع
        type_results = ScanResult.query.filter_by(scan_type=scan_type)
        total = type_results.count()
        
        if total > 0:
            threats = type_results.filter_by(is_threat=True).count()
            avg_time = db.session.query(func.avg(ScanResult.scan_time)).filter(ScanResult.scan_type == scan_type).scalar() or 0
            
            stats_by_type[scan_type] = {
                'type': {
                    'url': 'فحص الروابط',
                    'email': 'فحص البريد',
                    'file': 'فحص الملفات'
                }[scan_type],
                'count': total,
                'success_rate': round(((total - threats) / total) * 100, 1),
                'avg_time': round(avg_time * 1000, 0),  # تحويل إلى مللي ثانية
                'threats': threats
            }
    
    # الإحصائيات العامة
    total_scans = ScanResult.query.count()
    total_threats = ScanResult.query.filter_by(is_threat=True).count()
    warnings = ScanResult.query.filter_by(threat_level='medium').count()
    
    # حساب معدل الاستجابة (عدد الفحوصات في آخر ساعة)
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    response_rate = ScanResult.query.filter(ScanResult.scan_date >= hour_ago).count()
    
    data = {
        'successful_scans': total_scans - total_threats,
        'warnings': warnings,
        'threats': total_threats,
        'response_rate': response_rate,
        'detailed_stats': list(stats_by_type.values())
    }
    
    return render_template('scan_statistics.html', **data)

@app.route('/settings')
def settings():
    """صفحة الإعدادات"""
    return render_template('settings.html')

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    """صفحة الدعم الفني"""
    if request.method == 'POST':
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if not subject or not message:
            flash('الرجاء تعبئة جميع الحقول المطلوبة', 'error')
            return redirect(url_for('support'))
        
        try:
            # إنشاء رسالة دعم جديدة
            support_message = SupportMessage(
                user_id=session['user_id'],
                subject=subject,
                message=message
            )
            db.session.add(support_message)
            db.session.commit()
            
            # إنشاء إشعار للمشرفين
            username = User.query.get(session['user_id']).username
            create_admin_notification(
                title="رسالة دعم فني جديدة",
                message=f"تم استلام رسالة دعم فني جديدة من المستخدم {username}\nالموضوع: {subject}",
                type="support"
            )
            
            flash('تم إرسال رسالتك بنجاح. سنقوم بالرد عليك في أقرب وقت ممكن.', 'success')
            return redirect(url_for('support'))
            
        except Exception as e:
            logger.error(f"Error processing support message: {str(e)}")
            flash('عذراً، حدث خطأ أثناء إرسال رسالتك. الرجاء المحاولة مرة أخرى.', 'error')
            db.session.rollback()
            
    # عرض الرسائل السابقة للمستخدم
    user_messages = None
    if 'user_id' in session:
        user_messages = SupportMessage.query.filter_by(
            user_id=session['user_id']
        ).order_by(SupportMessage.created_at.desc()).all()
    
    return render_template('support.html', messages=user_messages)

@app.route('/admin/support')
@admin_required
def admin_support():
    """صفحة إدارة رسائل الدعم الفني"""
    try:
        messages = SupportMessage.query.order_by(SupportMessage.created_at.desc()).all()
        print(f"Found {len(messages)} support messages")  # Debug print
        
        # تحقق من وجود رسائل
        if not messages:
            flash('لا توجد رسائل دعم فني حالياً', 'info')
        
        return render_template('admin/support.html', messages=messages)
    except Exception as e:
        print(f"Error in admin_support: {str(e)}")  # Debug print
        flash('حدث خطأ أثناء جلب رسائل الدعم الفني', 'error')
        return render_template('admin/support.html', messages=[])

@app.route('/admin/support/<int:message_id>/status', methods=['POST'])
@admin_required
def update_support_status(message_id):
    """تحديث حالة رسالة الدعم"""
    message = SupportMessage.query.get_or_404(message_id)
    
    # محاولة الحصول على الحالة من form-data أو JSON
    status = None
    if request.is_json:
        status = request.json.get('status')
    else:
        status = request.form.get('status')
    
    if status not in ['pending', 'answered']:
        return jsonify({'status': 'error', 'message': 'حالة غير صالحة'}), 400
    
    try:
        message.status = status
        db.session.commit()
        
        # لا نقوم بإنشاء إشعار هنا لأنه سيتم إنشاؤه في دالة respond_to_support
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/support/<int:message_id>/respond', methods=['POST'])
def respond_to_support(message_id):
    """الرد على رسالة دعم فني"""
    message = SupportMessage.query.get_or_404(message_id)
    
    # محاولة الحصول على الرد من form-data أو JSON
    response_text = None
    if request.is_json:
        response_text = request.json.get('response')
    else:
        response_text = request.form.get('response')
    
    if not response_text:
        return jsonify({'status': 'error', 'message': 'الرد مطلوب'}), 400
        
    try:
        # إنشاء رد جديد
        response = SupportResponse(
            message_id=message_id,
            admin_id=session['user_id'],
            response_text=response_text
        )
        db.session.add(response)
        
        # تحديث حالة الرسالة
        message.status = 'answered'
        db.session.commit()
        
        # إنشاء إشعار واحد فقط للمستخدم
        create_notification(
            user_id=message.user_id,
            title='رد جديد على رسالة الدعم الفني',
            message=f'تم الرد على رسالتك بخصوص: {message.subject}\nالرد: {response_text[:100]}{"..." if len(response_text) > 100 else ""}',
            type='support'
        )
        
        return jsonify({
            'status': 'success',
            'response': {
                'id': response.id,
                'text': response_text,
                'admin_name': response.admin.username,
                'created_at': response.created_at.strftime('%Y-%m-%d %H:%M')
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/support/<int:message_id>/responses')
@admin_required
def get_support_responses(message_id):
    """جلب ردود رسالة دعم معينة"""
    responses = SupportResponse.query.filter_by(message_id=message_id).order_by(SupportResponse.created_at.desc()).all()
    return jsonify({
        'responses': [{
            'id': r.id,
            'text': r.response_text,
            'admin_name': r.admin.username,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M')
        } for r in responses]
    })

@app.route('/articles')
def articles():
    """صفحة قاعدة المعرفة والمقالات"""
    return render_template('articles.html')

@app.route('/phishing_guide')
def phishing_guide():
    """صفحة دليل التصيد"""
    return render_template('edu/phishing_guide.html')

@app.route('/best_practices')
def best_practices():
    """صفحة أفضل الممارسات"""
    return render_template('edu/best_practices.html')

@app.route('/security_awareness')
def security_awareness():
    """صفحة التوعية الأمنية"""
    return render_template('edu/security_awareness.html')

@app.route('/edu/educational_videos')
def educational_videos():
    """صفحة الفيديوهات التعليمية"""
    return render_template('edu/educational_videos.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """صفحة تسجيل الدخول"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
            
            # إنشاء إشعار للمشرفين عند تسجيل دخول مستخدم جديد
            if not user.is_admin:
                create_admin_notification(
                    title="تسجيل دخول مستخدم جديد",
                    message=f"قام المستخدم {username} بتسجيل الدخول في {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    type="security"
                )
            
            flash('تم تسجيل الدخول بنجاح!', 'success')
            next_page = request.args.get('next')
            
            if user.is_admin and not next_page:
                return redirect(url_for('admin_dashboard'))
            
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """صفحة التسجيل"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # التحقق من وجود جميع الحقول المطلوبة
        if not all([username, email, password, confirm_password]):
            flash('جميع الحقول مطلوبة', 'error')
            return render_template('register.html')

        # التحقق من تطابق كلمات المرور
        if password != confirm_password:
            flash('كلمات المرور غير متطابقة', 'error')
            return render_template('register.html')

        # التحقق من عدم وجود المستخدم مسبقاً
        if User.query.filter_by(username=username).first():
            flash('اسم المستخدم مستخدم بالفعل', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('البريد الإلكتروني مستخدم بالفعل', 'error')
            return render_template('register.html')

        try:
            # إنشاء مستخدم جديد
            user = User(
                username=username,
                email=email,
                is_admin=False
            )
            user.set_password(password)
            
            # حفظ المستخدم في قاعدة البيانات
            db.session.add(user)
            db.session.commit()

            # إنشاء إشعار للمشرفين
            create_admin_notification(
                title="تسجيل مستخدم جديد",
                message=f"قام {username} بإنشاء حساب جديد",
                type="user_registration"
            )

            flash('تم إنشاء حسابك بنجاح! يمكنك الآن تسجيل الدخول', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'حدث خطأ أثناء إنشاء الحساب: {str(e)}', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/logout')
def logout():
    """تسجيل الخروج"""
    session.pop('user_id', None)
    session.pop('is_admin', None)  # إزالة حالة المشرف
    flash('تم تسجيل الخروج بنجاح', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    """صفحة الملف الشخصي"""
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/notifications')
@login_required
def notifications():
    """صفحة الإشعارات"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    notifications = Notification.query.filter_by(user_id=session['user_id']).order_by(
        Notification.created_at.desc()
    ).paginate(page=page, per_page=per_page)
    
    # تحديث حالة الإشعارات غير المقروءة
    unread = Notification.query.filter_by(user_id=session['user_id'], is_read=False).all()
    for notification in unread:
        notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/notifications/unread')
@login_required
def unread_notifications_count():
    try:
        unread = Notification.query.filter_by(
            user_id=session['user_id'],
            is_read=False
        ).order_by(Notification.created_at.desc()).limit(3).all()
        
        notifications = []
        for n in unread:
            # تقصير العنوان إلى 15 حرف كحد أقصى
            title = n.title[:12] + '...' if len(n.title) > 15 else n.title
            
            # تقصير الرسالة إلى 20 حرف كحد أقصى
            message = n.message.split('\n')[0]
            message = message[:17] + '...' if len(message) > 20 else message
            
            # تنسيق الوقت بشكل مختصر
            time_diff = datetime.utcnow() - n.created_at
            if time_diff.days > 0:
                time_str = f"{time_diff.days}ي"
            elif time_diff.seconds // 3600 > 0:
                time_str = f"{time_diff.seconds // 3600}س"
            else:
                time_str = f"{time_diff.seconds // 60}د"
            
            notifications.append({
                'id': n.id,
                'title': title,
                'message': message,
                'type': n.type,
                'time': time_str,
                'is_read': n.is_read
            })
        
        total = Notification.query.filter_by(
            user_id=session['user_id'],
            is_read=False
        ).count()
        
        return jsonify({
            'count': total,
            'notifications': notifications,
            'has_more': total > 3
        })
    except Exception as e:
        logger.error(f"Error in unread_notifications_count: {str(e)}")
        return jsonify({
            'count': 0,
            'notifications': [],
            'error': 'حدث خطأ في جلب الإشعارات'
        }), 500

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    """تحديث جميع الإشعارات كمقروءة"""
    try:
        Notification.query.filter_by(
            user_id=session['user_id'],
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error marking notifications as read: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)})

def create_notification(user_id, title, message, type='system'):
    """إنشاء إشعار جديد للمستخدم"""
    notification = Notification(
        user_id=user_id,
        title=title,
        message=message,
        type=type,
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()
    return notification

def create_admin_notification(title, message, type='system'):
    """إنشاء إشعار لجميع المشرفين"""
    admins = User.query.filter_by(is_admin=True).all()
    for admin in admins:
        notification = Notification(
            user_id=admin.id,
            title=title,
            message=message,
            type=type,
            is_read=False
        )
        db.session.add(notification)
    db.session.commit()

# Admin dashboard routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    """صفحة لوحة تحكم المشرف"""
    # إحصائيات عامة
    total_users = User.query.count()
    total_scans = ScanResult.query.count()
    total_threats = ScanResult.query.filter_by(is_threat=True).count()
    
    # آخر المستخدمين المسجلين
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    # آخر عمليات الفحص
    recent_scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(10).all()
    
    # إحصائيات حسب نوع الفحص
    url_scans = ScanResult.query.filter_by(scan_type='url').count()
    email_scans = ScanResult.query.filter_by(scan_type='email').count()
    file_scans = ScanResult.query.filter_by(scan_type='file').count()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_scans=total_scans,
                         total_threats=total_threats,
                         recent_users=recent_users,
                         recent_scans=recent_scans,
                         url_scans=url_scans,
                         email_scans=email_scans,
                         file_scans=file_scans)

@app.route('/admin/users')
@admin_required
def admin_users():
    """إدارة المستخدمين"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/scans')
@admin_required
def admin_scans():
    """سجل عمليات الفحص"""
    scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).all()
    return render_template('admin/scans.html', scans=scans)

@app.route('/admin/threats')
@admin_required
def admin_threats():
    """التهديدات المكتشفة"""
    threats = ScanResult.query.filter_by(is_threat=True).order_by(ScanResult.scan_date.desc()).all()
    return render_template('admin/threats.html', threats=threats)

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """إعدادات النظام"""
    return render_template('admin/settings.html')

# Admin API endpoints
@app.route('/admin/api/user/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """حذف مستخدم"""
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({'error': 'لا يمكن حذف حساب المشرف'}), 403
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'تم حذف المستخدم بنجاح'})

@app.route('/admin/api/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    """تغيير صلاحيات المستخدم"""
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    return jsonify({'message': 'تم تحديث صلاحيات المستخدم', 'is_admin': user.is_admin})

@app.route('/admin/api/stats')
@admin_required
def admin_stats():
    """إحصائيات لوحة التحكم في الوقت الفعلي"""
    # إحصائيات عامة
    total_users = User.query.count()
    total_scans = ScanResult.query.count()
    total_threats = ScanResult.query.filter_by(is_threat=True).count()
    
    # آخر المستخدمين المسجلين
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_users_data = [{
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.strftime('%Y-%m-%d')
    } for user in recent_users]
    
    # آخر عمليات الفحص
    recent_scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(10).all()
    recent_scans_data = [{
        'scan_type': scan.scan_type,
        'is_threat': scan.is_threat,
        'threat_level': scan.threat_level,
        'scan_date': scan.scan_date.strftime('%Y-%m-%d %H:%M')
    } for scan in recent_scans]
    
    # إحصائيات حسب نوع الفحص
    url_scans = ScanResult.query.filter_by(scan_type='url').count()
    email_scans = ScanResult.query.filter_by(scan_type='email').count()
    file_scans = ScanResult.query.filter_by(scan_type='file').count()
    
    # إحصائيات التهديدات حسب المستوى
    high_threats = ScanResult.query.filter_by(is_threat=True, threat_level='high').count()
    medium_threats = ScanResult.query.filter_by(is_threat=True, threat_level='medium').count()
    low_threats = ScanResult.query.filter_by(is_threat=True, threat_level='low').count()
    
    # معدل النجاح لكل نوع
    url_success_rate = calculate_success_rate('url')
    email_success_rate = calculate_success_rate('email')
    file_success_rate = calculate_success_rate('file')
    
    return jsonify({
        'total_users': total_users,
        'total_scans': total_scans,
        'total_threats': total_threats,
        'recent_users': recent_users_data,
        'recent_scans': recent_scans_data,
        'scan_stats': {
            'url': {
                'total': url_scans,
                'success_rate': url_success_rate
            },
            'email': {
                'total': email_scans,
                'success_rate': email_success_rate
            },
            'file': {
                'total': file_scans,
                'success_rate': file_success_rate
            }
        },
        'threat_levels': {
            'high': high_threats,
            'medium': medium_threats,
            'low': low_threats
        }
    })

def calculate_success_rate(scan_type):
    """حساب معدل النجاح لنوع معين من الفحص"""
    total = ScanResult.query.filter_by(scan_type=scan_type).count()
    if total == 0:
        return 100.0
    threats = ScanResult.query.filter_by(scan_type=scan_type, is_threat=True).count()
    return round(((total - threats) / total) * 100, 1)

@app.route('/admin/api/users', methods=['POST'])
@admin_required
def add_user():
    """إضافة مستخدم جديد"""
    data = request.get_json()
    
    # التحقق من البيانات المطلوبة
    if not all(key in data for key in ['username', 'email', 'password']):
        return jsonify({'error': 'جميع الحقول مطلوبة'}), 400
        
    # التحقق من عدم وجود المستخدم مسبقاً
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'اسم المستخدم مستخدم بالفعل'}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'البريد الإلكتروني مستخدم بالفعل'}), 400
    
    try:
        # إنشاء مستخدم جديد
        user = User(
            username=data['username'],
            email=data['email'],
            is_admin=data.get('is_admin', False)
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'message': 'تم إضافة المستخدم بنجاح',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'حدث خطأ أثناء إضافة المستخدم: {str(e)}'}), 500

# Add template context processor
@app.context_processor
def utility_processor():
    return {
        'User': User
    }

@app.route('/notifications/mark-read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """تحديث حالة إشعار معين كمقروء"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id,
            user_id=session['user_id']
        ).first()
        
        if notification:
            notification.is_read = True
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'message': 'الإشعار غير موجود'}), 404
            
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/support/<int:message_id>/details')
@admin_required
def get_message_details(message_id):
    """جلب تفاصيل رسالة الدعم"""
    message = SupportMessage.query.get_or_404(message_id)
    return jsonify({
        'id': message.id,
        'subject': message.subject,
        'message': message.message,
        'username': message.user.username,
        'status': message.status,
        'created_at': message.created_at.strftime('%Y-%m-%d %H:%M')
    })

@app.route('/admin/api/support/count')
@admin_required
def get_support_count():
    """جلب عدد رسائل الدعم التي تحتاج للرد"""
    count = SupportMessage.query.filter_by(status='pending').count()
    return jsonify({'count': count})

@app.context_processor
def inject_support_data():
    """حقن بيانات الدعم الفني في قوالب المشرف"""
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user and user.is_admin:
            latest_messages = SupportMessage.query.order_by(
                SupportMessage.created_at.desc()
            ).limit(5).all()
            pending_count = SupportMessage.query.filter_by(status='pending').count()
            return {
                'latest_support_messages': latest_messages,
                'support_messages_count': pending_count
            }
    return {}

@app.route('/support/chat/<int:message_id>/messages')
@login_required
def get_chat_messages(message_id):
    """جلب رسائل المحادثة"""
    support_message = SupportMessage.query.get_or_404(message_id)
    
    # التحقق من الصلاحية
    if not session.get('is_admin') and support_message.user_id != session['user_id']:
        return jsonify({'error': 'غير مصرح لك بالوصول إلى هذه المحادثة'}), 403
    
    messages = ChatMessage.query.filter_by(support_message_id=message_id).order_by(ChatMessage.created_at).all()
    
    # تحديث حالة القراءة للرسائل
    for msg in messages:
        if msg.sender_id != session['user_id'] and not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'sender_id': msg.sender_id,
            'sender_name': msg.sender.username,
            'message': msg.message,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M'),
            'is_read': msg.is_read,
            'is_admin': msg.sender.is_admin
        } for msg in messages]
    })

@app.route('/support/chat/<int:message_id>/send', methods=['POST'])
@login_required
def send_chat_message(message_id):
    """إرسال رسالة في المحادثة"""
    support_message = SupportMessage.query.get_or_404(message_id)
    
    # التحقق من الصلاحية
    if not session.get('is_admin') and support_message.user_id != session['user_id']:
        return jsonify({'error': 'غير مصرح لك بالإرسال في هذه المحادثة'}), 403
    
    message_text = request.json.get('message')
    if not message_text:
        return jsonify({'error': 'الرسالة مطلوبة'}), 400
    
    try:
        # إنشاء رسالة جديدة
        chat_message = ChatMessage(
            support_message_id=message_id,
            sender_id=session['user_id'],
            message=message_text
        )
        db.session.add(chat_message)
        
        # تحديث حالة الرسالة إذا كان المرسل مشرف
        if session.get('is_admin') and support_message.status == 'pending':
            support_message.status = 'in_progress'
        
        db.session.commit()
        
        # إنشاء إشعار للطرف الآخر
        recipient_id = support_message.user_id if session.get('is_admin') else User.query.filter_by(is_admin=True).first().id
        create_notification(
            user_id=recipient_id,
            title='رسالة جديدة في المحادثة',
            message=f'لديك رسالة جديدة في المحادثة: {support_message.subject}',
            type='support'
        )
        
        return jsonify({
            'status': 'success',
            'message': {
                'id': chat_message.id,
                'sender_id': chat_message.sender_id,
                'sender_name': chat_message.sender.username,
                'message': chat_message.message,
                'created_at': chat_message.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_read': False,
                'is_admin': session.get('is_admin', False)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/support/chat/<int:message_id>/mark-read', methods=['POST'])
@login_required
def mark_chat_messages_read(message_id):
    """تحديث حالة قراءة الرسائل"""
    try:
        ChatMessage.query.filter(
            ChatMessage.support_message_id == message_id,
            ChatMessage.sender_id != session['user_id'],
            ChatMessage.is_read == False
        ).update({'is_read': True})
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/password_strength')
def password_strength():
    """صفحة فحص قوة كلمة المرور"""
    return render_template('password_strength.html')

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    try:
        app.run(debug=True, use_reloader=True)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}")
        logger.error(traceback.format_exc())

with app.app_context():
    user = User.query.filter_by(username="Osama").first()
    if user:
        user.is_admin = True
        db.session.commit()
        print("تم تحديث الصلاحيات بنجاح!")
        print(f"اسم المستخدم: {user.username}")
        print(f"البريد الإلكتروني: {user.email}") 