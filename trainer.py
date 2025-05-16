import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report

# 1. Load and clean first dataset (spamV2.csv)
df1 = pd.read_csv(
    'spamV2.csv',
    header=None,
    names=['label', 'text'],
    usecols=[0, 1],
    encoding='latin1',
    skipinitialspace=True,
    on_bad_lines='skip'
)

# 2. Load and clean second dataset (spam.csv)
df2 = pd.read_csv(
    'spam.csv',
    header=None,
    names=['label', 'text'],
    usecols=[0, 1],
    encoding='latin1',
    skipinitialspace=True,
    on_bad_lines='skip'
)

# 3. Combine datasets
df = pd.concat([df1, df2], ignore_index=True)

# 4. Drop rows with missing values in label or text
df = df.dropna(subset=['label', 'text'])

# 5. Normalize text and labels
df['label'] = df['label'].str.strip().str.lower()
df['text'] = df['text'].str.strip()

# 6. Filter to only valid labels
df = df[df['label'].isin(['ham', 'spam'])]

# 7. Map labels to numeric for training
df['label_num'] = df['label'].map({'ham': 0, 'spam': 1})

# 8. Prepare features and target
X = df['text']
y = df['label_num']

# 9. Text vectorization with TF-IDF
vectorizer = TfidfVectorizer(stop_words='english', max_df=0.9, min_df=2)
X_vec = vectorizer.fit_transform(X)

# 10. Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42, stratify=y
)

# 11. Train Multinomial Naive Bayes model
model = MultinomialNB()
model.fit(X_train, y_train)

# 12. Predict and evaluate
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['ham', 'spam']))

# 13. Save the trained model and vectorizer
joblib.dump(model, 'spam_classifier_model.pkl')
joblib.dump(vectorizer, 'vector.pkl')

print("Training complete. Model and vectorizer saved.")
