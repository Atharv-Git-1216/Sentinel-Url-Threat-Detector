import re
from urllib.parse import urlparse

def extract_url_features(url):
    """
    Dissects the URL into mathematical features.
    """
    features = {}
    
    # Ensure URL has a scheme (http/https) for accurate parsing
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # 1. Basic Length (Phishing URLs often hide the domain in a long string)
    features['url_length'] = len(url)
    
    # 2. Dot Count (Excessive subdomains like 'login.paypal.secure.com')
    features['dot_count'] = domain.count('.')
    
    # 3. IP Check (Legitimate sites almost never use raw IP addresses)
    ip_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    features['is_ip'] = 1 if re.search(ip_pattern, domain) else 0
    
    # 4. Special Characters (The '@' symbol or excessive hyphens)
    features['has_at_symbol'] = 1 if "@" in url else 0
    features['hyphen_count'] = domain.count('-')
    
    return features, url

def calculate_risk_score(features):
    """
    The heuristic 'Brain' that evaluates the risk of the features.
    """
    risk_score = 0
    red_flags = []

    # Weighted Logic
    if features['is_ip'] == 1:
        risk_score += 50
        red_flags.append("Uses raw IP address instead of domain")
    
    if features['has_at_symbol'] == 1:
        risk_score += 40
        red_flags.append("Contains '@' symbol (used to spoof destination)")

    if features['dot_count'] > 3:
        risk_score += 20
        red_flags.append("Excessive subdomains detected")

    if features['url_length'] > 75:
        risk_score += 15
        red_flags.append("Unusually long URL (often used to hide malicious paths)")

    if features['hyphen_count'] > 1:
        risk_score += 10
        red_flags.append("Multiple hyphens in domain (common in brand impersonation)")

    # Normalize score to 100%
    final_score = min(risk_score, 100)
    
    # Categorization
    if final_score >= 50:
        severity = "HIGH"
        verdict = "Malicious"
    elif final_score >= 20:
        severity = "MEDIUM"
        verdict = "Suspicious"
    else:
        severity = "LOW"
        verdict = "Safe"

    return final_score, severity, verdict, red_flags

# --- Test Interface ---
if __name__ == "__main__":
    print("🌐 Sentinel Phase 2: URL Threat Detector")
    print("-----------------------------------------")
    target = input("Enter URL to scan: ").strip()
    
    if target:
        feats, cleaned_url = extract_url_features(target)
        score, sev, verdict, flags = calculate_risk_score(feats)
        
        print(f"\n[+] Analyzing: {cleaned_url}")
        print(f"[+] Risk Score: {score}/100")
        print(f"[+] Severity: {sev}")
        print(f"[+] Verdict: {verdict}")
        
        if flags:
            print("\n🚨 DETECTED RED FLAGS:")
            for flag in flags:
                print(f" - {flag}")
        else:
            print("\n✅ No obvious structural threats detected.")
    else:
        print("Error: No URL provided.")