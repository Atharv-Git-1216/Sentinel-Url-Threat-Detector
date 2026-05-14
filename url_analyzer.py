import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import os
import whois
from datetime import datetime

# Load the AI Brain
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
    
    features['domain'] = domain # Save domain for WHOIS lookup
    features['url_length'] = len(url)
    features['dot_count'] = domain.count('.')
    
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    features['is_ip'] = 1 if re.search(ip_pattern, domain) else 0
    features['has_at_symbol'] = 1 if "@" in url else 0
    features['hyphen_count'] = domain.count('-')
    
    return features, url

def check_domain_age(domain):
    """
    Reaches out to global WHOIS registries to find out when the domain was created.
    """
    try:
        # Ignore raw IPs for WHOIS
        if re.match(r"^[0-9\.]+$", domain):
            return None 
            
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # Sometimes WHOIS returns a list of dates, we just need the first one
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_in_days = (datetime.now() - creation_date).days
            return age_in_days
    except Exception:
        # WHOIS lookups can fail or be blocked, we handle this gracefully
        pass
    
    return None

def calculate_risk_score(features):
    """
    The Hybrid Brain: Combines Machine Learning with External Threat Intelligence.
    """
    red_flags = []
    
    # 1. Structural Checks
    if features['is_ip'] == 1: red_flags.append("Uses raw IP address")
    if features['has_at_symbol'] == 1: red_flags.append("Contains '@' symbol")
    if features['url_length'] > 75: red_flags.append("Unusually long URL")

    # 2. External Threat Intel (WHOIS)
    print(f"🔍 Running background check on domain: {features['domain']}...")
    domain_age = check_domain_age(features['domain'])
    
    if domain_age is not None:
        if domain_age < 30:
            red_flags.append(f"CRITICAL: Domain is extremely new ({domain_age} days old)")
    else:
        red_flags.append("WHOIS data hidden or unreachable (Suspicious)")

    # 3. Machine Learning Prediction
    if ai_model:
        feature_df = pd.DataFrame([{
            'url_length': features['url_length'],
            'dot_count': features['dot_count'],
            'is_ip': features['is_ip'],
            'has_at_symbol': features['has_at_symbol'],
            'hyphen_count': features['hyphen_count']
        }])

        prediction = ai_model.predict(feature_df)[0]
        confidence_score = round(ai_model.predict_proba(feature_df)[0][prediction] * 100, 2)
        base_score = int(confidence_score) if prediction == 1 else int(100 - confidence_score)
    else:
        base_score = 0
        confidence_score = 0

    # 4. The Final Verdict Logic
    # If the domain is brand new, we OVERRIDE the AI and force a High Risk score
    if domain_age is not None and domain_age < 30:
        final_score = max(base_score, 85) # Force score to at least 85%
        severity = "HIGH"
        verdict = f"Malicious (Forced by Threat Intel - New Domain)"
    else:
        final_score = base_score
        if final_score >= 50:
            severity = "HIGH"
            verdict = f"Malicious (AI Confidence: {confidence_score}%)"
        elif final_score >= 20:
            severity = "MEDIUM"
            verdict = f"Suspicious (AI Confidence: {confidence_score}%)"
        else:
            severity = "LOW"
            verdict = f"Safe (AI Confidence: {confidence_score}%)"
            
    # Add domain age info to flags for the user to see
    if domain_age:
        red_flags.insert(0, f"Domain Age: {domain_age} days")

    return final_score, severity, verdict, red_flags