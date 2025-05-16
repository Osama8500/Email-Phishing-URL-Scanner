import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# تحميل البيانات (غيّر هذا حسب طريقة تحميلك)
df = pd.read_csv("phishing.csv")  # أو اسم ملفك

# تحديد الفيتشرات والهدف
features = ['UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
            'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort',
            'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags',
            'ServerFormHandler', 'InfoEmail', 'AbnormalURL', 'WebsiteForwarding',
            'StatusBarCust', 'DisableRightClick', 'UsingPopupWindow',
            'IframeRedirection', 'AgeofDomain', 'DNSRecording', 'WebsiteTraffic',
            'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport']

X = df[features]
y = df['class']  # غيّر الاسم إذا عندك اسم ثاني للهدف

# تقسيم البيانات
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# إنشاء النموذج بالتفاصيل اللي طلعت من الملف
model = GradientBoostingClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=3,
    loss='log_loss',
    criterion='friedman_mse'
)

# تدريب النموذج
model.fit(X_train, y_train)

# التقييم
y_pred = model.predict(X_test)
print("الدقة:", accuracy_score(y_test, y_pred))

# حفظ النموذج إذا حبيت
import pickle
with open('newmodel.pkl', 'wb') as f:
    pickle.dump(model, f)
