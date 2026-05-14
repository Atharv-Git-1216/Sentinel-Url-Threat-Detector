import pandas as pd
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

print("🧠 Booting up Sentinel ML Training Facility...")

# 1. Generate Synthetic Training Data
# In a real scenario, you'd load this from a CSV: df = pd.read_csv('urls.csv')
data = []
for _ in range(1000):
    # Simulate Safe URLs
    data.append({
        'url_length': random.randint(15, 60),
        'dot_count': random.randint(1, 2),
        'is_ip': 0,
        'has_at_symbol': 0,
        'hyphen_count': random.randint(0, 1),
        'label': 0 # 0 = Safe
    })
    # Simulate Malicious URLs
    data.append({
        'url_length': random.randint(50, 150),
        'dot_count': random.randint(2, 6),
        'is_ip': random.choice([0, 1, 1]), # Higher chance of IP
        'has_at_symbol': random.choice([0, 1]),
        'hyphen_count': random.randint(1, 5),
        'label': 1 # 1 = Malicious
    })

df = pd.DataFrame(data)

# 2. Split into Features (X) and Target (y)
X = df.drop('label', axis=1)
y = df['label']

# Split into training and testing sets (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 3. Initialize and Train the Random Forest
print("🌲 Training Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Test the Model's Accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

# 5. Save the Brain to disk
joblib.dump(model, 'sentinel_url_model.pkl')
print("✅ Model successfully saved as 'sentinel_url_model.pkl'")