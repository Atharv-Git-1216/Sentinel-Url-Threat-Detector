from flask import Flask, request, jsonify
from supabase import create_client, Client
import os

# Import the brain from your other file!
from url_analyzer import extract_url_features, calculate_risk_score

app = Flask(__name__)

# --- Supabase Configuration ---
SUPABASE_URL = "https://qtgzoyehjsjvmanhjsxs.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF0Z3pveWVoanNqdm1hbmhqc3hzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg2MTQ3MjQsImV4cCI6MjA5NDE5MDcyNH0.p2NtYPlJOXIGDzG02n2R71_fojslmIMmnE16wCN4Zd4"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- The API Endpoint ---
@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.get_json()
    
    # Validation
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' field in request"}), 400
        
    target_url = data['url']
    
    # 1. Run the URL through our logic
    feats, cleaned_url = extract_url_features(target_url)
    score, sev, verdict, flags = calculate_risk_score(feats)
    
    # 2. Log the scan to Supabase
    try:
        supabase.table("sentinel_urls").insert({
            "url": cleaned_url,
            "risk_score": score,
            "severity": sev,
            "verdict": verdict,
            "red_flags": flags 
        }).execute()
    except Exception as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500
        
    # 3. Return the payload to the user
    response = {
        "status": "success",
        "analyzed_url": cleaned_url,
        "threat_assessment": {
            "score_out_of_100": score,
            "severity": sev,
            "verdict": verdict,
            "red_flags": flags
        }
    }
    return jsonify(response), 200

if __name__ == '__main__':
    print("👁️ Sentinel URL Scanner API is live on port 5001...")
    # Port 5001 prevents conflicts with the Password Analyzer on 5000
    app.run(debug=True, port=5001)