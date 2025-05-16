import pandas as pd
import joblib
from sklearn.metrics import accuracy_score

# تحميل البيانات
df = pd.read_csv('spam.csv', encoding='latin1')  # بعض الرسائل فيها رموز خاصة

# إعادة تسمية الأعمدة لأن بعض الأعمدة فارغة
df = df.rename(columns={'v1': 'label', 'v2': 'body'})

# أخذ فقط الأعمدة المهمة
df = df[['label', 'body']]

# تحويل التسميات النصية إلى أرقام
df['label'] = df['label'].map({'ham': 0, 'spam': 1})

# فصل الميزات (النص) والهدف
X = df['body']
y = df['label']

# تحميل vectorizer والنموذج
vectorizer = joblib.load('vec.pkl')
model = joblib.load('spam.pkl')

# تحويل النصوص إلى فيتشرات
X_vectorized = vectorizer.transform(X)

# التنبؤ
y_pred = model.predict(X_vectorized)

# حساب الدقة
accuracy = accuracy_score(y, y_pred)
print(f"Accuracy: {accuracy:.2f}")
