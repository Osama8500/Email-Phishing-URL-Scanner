from flask import Flask, render_template, request  # Flask web framework
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app and upload folder
app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.secret_key = 'your-secret-key-here'  # needed for flash messages
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

print("Loading models...")
try:
    logger.info("Loading URL model...")
    with open('newmodel.pkl', 'rb') as f:
        url_model = pickle.load(f)           # URL phishing detection model
    logger.info("URL model loaded successfully")
    
    logger.info("Loading message model...")
    msg_model = joblib.load('spam_model.pkl')
    vectorizer = joblib.load('vector.pkl')   # Email text vectorizer
    
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

def scan_url(url):
    """فحص رابط واحد للتحقق من كونه مشبوه"""
    details, risk_score = analyze_url_details(url)
    
    if not details:  # إذا لم يتم العثور على أي مشاكل في التحليل اليدوي
        try:
            feats = FeatureExtraction(url).getFeaturesList()
            n = url_model.n_features_in_
            feats = (feats + [0]*n)[:n]
            x = np.array(feats).reshape(1, n)
            pred = url_model.predict(x)[0]
            
            if pred == 1:  # إذا صنف النموذج الرابط كآمن
                return {
                    'url': url,
                    'status': 'safe',
                    'reason': 'تم التحقق من أمان الرابط',
                    'probability': 100 - risk_score,
                    'details': []
                }
        except Exception as e:
            pass

    return {
        'url': url,
        'status': 'malicious' if risk_score > 50 else 'safe',
        'reason': details[0] if details else 'تم اكتشاف مخاطر محتملة',
        'probability': risk_score,
        'details': details
    }

def scan_email(content):
    """Scan email content: keyword, text model, LIME, and embedded URLs"""
    reasons = []
    safety_score = 0
    total_checks = 0
    has_malicious_url = False
    
    # 1. Keyword check
    kws = check_spam_keywords(content)
    if kws:
        safety_percentage = 30
        reasons.append(f"تم اكتشاف كلمات مشبوهة: {', '.join(kws)}")
        reasons.insert(0, "تم تصنيف البريد كمشبوه لوجود كلمات مشبوهة")
        return 'Spam', reasons, [], safety_percentage
    
    safety_score += 1
    total_checks += 1

    # 2. Text classification
    clean = remove_urls(content)
    vec = vectorizer.transform([clean])
    txt_pred = msg_model.predict(vec)[0]
    txt_proba = msg_model.predict_proba(vec)[0]
    if txt_pred == 0:
        safety_score += 1
        reasons.append(f"تصنيف النص: آمن (نسبة الثقة: {txt_proba[0]:.0%})")
    else:
        reasons.append(f"تصنيف النص: خطر (نسبة الثقة: {txt_proba[1]:.0%})")
    total_checks += 1

    # 3. LIME explanation
    explanations = explain_email(clean)
    if explanations:
        reasons.append("تحليل المحتوى:")
        for feat, weight in explanations:
            if abs(weight) > 0.1:
                direction = "يقلل" if weight > 0 else "يزيد"
                reasons.append(f"- {feat}: {direction} من احتمالية الخطورة بنسبة {abs(weight):.0%}")

    # 4. URL checks
    url_results = []
    urls = extract_urls(content)
    if urls:
        for u in urls:
            res = scan_url(u)
            url_results.append(res)
            if res['status'] == 'malicious':
                has_malicious_url = True
                reasons.append(f"رابط مشبوه: {u} ({res['reason']})")
        total_checks += 1

    if total_checks > 0:
        safety_percentage = (safety_score / total_checks) * 100
    else:
        safety_percentage = 0

    if has_malicious_url:
        safety_percentage = min(safety_percentage, 40)
        reasons.insert(0, "تم تخفيض نسبة الأمان بسبب وجود روابط مشبوهة")

    final = 'Ham' if safety_percentage >= 50 else 'Spam'
    return final, reasons, url_results, safety_percentage

def scan_pe(filepath):
    """Perform PE or text scan on uploaded file or extracted archive contents"""
    results = []
    fname = os.path.basename(filepath)
    ext = os.path.splitext(fname)[1].lower()
    
    if ext in ['.zip', '.rar']:
        with tempfile.TemporaryDirectory() as tmp:
            if extract_archive(filepath, tmp):
                for root, _, files in os.walk(tmp):
                    for fn in files:
                        results += scan_pe(os.path.join(root, fn))
    elif ext == '.txt':
        text_res = scan_text_file(filepath)
        is_suspicious = bool(text_res)
        
        danger_score = 0
        if 'suspicious_urls' in text_res:
            url_count = text_res['suspicious_urls']['count']
            danger_score = min(100, danger_score + (url_count * 20))
        
        danger_score = min(100, danger_score + (len(text_res) * 15))
        safety_score = 100 - danger_score
        label = 'مشبوه' if is_suspicious else 'آمن'
        
        results.append({
            'filename': fname,
            'type': 'Text',
            'label': label,
            'confidence': safety_score,
            'details': text_res
        })
    else:
        try:
            df = extract_pe_features(filepath)
            pred = pe_model.predict(df)[0]
            proba = pe_model.predict_proba(df)[0]
            label = 'آمن' if pred == 1 else 'ضار'
            results.append({
                'filename': fname,
                'type': 'PE',
                'label': label,
                'confidence': round(max(proba)*100,2),
                'details': {}
            })
        except Exception as e:
            results.append({
                'filename': fname,
                'type': 'Unknown',
                'label': 'غير معروف',
                'confidence': 50,
                'details': {'error': 'لا يمكن فحص هذا النوع من الملفات'}
            })
    return results 