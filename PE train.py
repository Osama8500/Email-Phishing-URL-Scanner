import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pickle

# 1. قراءة البيانات
df = pd.read_csv('data_file.csv')

# 2. فصل أعمدة المعرفات للتتبُّع لاحقاً
df_ids = df[['FileName', 'md5Hash']]

# 3. تجهيز الميزات والهدف
X = df.drop(columns=['FileName', 'md5Hash', 'Benign'])
y = df['Benign']

# 4. تقسيم البيانات (80% تدريب، 20% اختبار)
X_train, X_test, y_train, y_test, ids_train, ids_test = train_test_split(
    X, y, df_ids,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# 5. إنشاء نموذج غابة عشوائية وتدريبه
clf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'  # لو البيانات غير متوازنة
)
clf.fit(X_train, y_train)

# 6. تقييم النموذج
y_pred  = clf.predict(X_test)
y_proba = clf.predict_proba(X_test)[:, 1]

print("=== Classification Report ===")
print(classification_report(y_test, y_pred))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))
print("=== ROC AUC ===")
print(roc_auc_score(y_test, y_proba))

# 7. حفظ الموديل للتشغيل لاحقاً (مثلاً في Flask)
with open('malware_model.pkl', 'wb') as f:
    pickle.dump(clf, f)

# 8. دمج النتائج مع المعرفات وتصديرها
results = ids_test.copy()
results['TrueLabel']      = y_test.values
results['PredictedLabel'] = y_pred
results['Probability']    = y_proba
results.to_csv('predictions_with_ids.csv', index=False)

print("\n✅ الموديل محفوظ في 'malware_model.pkl'، والنتائج في 'predictions_with_ids.csv'")
