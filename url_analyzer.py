import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import os

# Load the AI Brain (ensure it exists)
MODEL_PATH = 'sentinel_url_model.pkl'
if os.path.exists(MODEL_PATH):
    ai_model = joblib.load(MODEL_PATH)
else:
    ai_model = None
    print("⚠️ Warning: ML Model not found. Run train_model.py first.")

def extract_url_features(url):
    features = {}
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    features['url_length'] = len(url)
    features['dot_count'] = domain.count('.')
    
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    features['is_ip'] = 1 if re.search(ip_pattern, domain) else 0
    features['has_at_symbol'] = 1 if "@" in url else 0
    features['hyphen_count'] = domain.count('-')
    
    return features, url

def calculate_risk_score(features):
    """
    The ML-Powered Brain.
    """
    red_flags = []
    
    # Still keep our flags for user context
    if features['is_ip'] == 1: red_flags.append("Uses raw IP address")
    if features['has_at_symbol'] == 1: red_flags.append("Contains '@' symbol")
    if features['url_length'] > 75: red_flags.append("Unusually long URL")

    if not ai_model:
        return 0, "UNKNOWN", "Model Missing", red_flags

    # Convert features to a format the model understands (DataFrame)
    # The order must match the training data exactly!
    feature_df = pd.DataFrame([{
        'url_length': features['url_length'],
        'dot_count': features['dot_count'],
        'is_ip': features['is_ip'],
        'has_at_symbol': features['has_at_symbol'],
        'hyphen_count': features['hyphen_count']
    }])

    # Ask the AI for a prediction (0 = Safe, 1 = Malicious)
    prediction = ai_model.predict(feature_df)[0]
    
    # Ask the AI how confident it is (Probability)
    probabilities = ai_model.predict_proba(feature_df)[0]
    confidence_score = round(probabilities[prediction] * 100, 2)

    if prediction == 1:
        severity = "HIGH"
        verdict = f"Malicious (AI Confidence: {confidence_score}%)"
        risk_score = int(confidence_score) # Use confidence as the risk score
    else:
        severity = "LOW"
        verdict = f"Safe (AI Confidence: {confidence_score}%)"
        risk_score = int(100 - confidence_score)

    return risk_score, severity, verdict, red_flags