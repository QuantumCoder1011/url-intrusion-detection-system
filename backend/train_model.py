import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# We will generate a synthetic dataset based on our known attack patterns and some benign traffic
# In a real-world scenario, you would replace this with a large CSV dataset (e.g., from Kaggle)

BENIGN_URLS = [
    "/index.html", "/about", "/contact", "/api/users?id=123", "/products?category=books&page=2",
    "/assets/style.css", "/images/logo.png", "/login", "/search?q=hello", "/",
    "/dashboard", "/settings", "/profile?user=vansh", "/api/data", "/download?file=report.pdf"
]

MALICIOUS_URLS = [
    # SQLi
    "/?id=1' OR 1=1#", "/search?q=test' UNION SELECT * FROM users--", "/api?id=1; DROP TABLE users--",
    "/page?name=admin'", "/login?user=admin' OR '1'='1", "/page?id=1 AND 1=1--",
    # XSS
    "/?q=%27", "/comment?text=<img src=x onerror=alert(document.cookie)>", "/?x=%3C%20script",
    "/page?x=<body onload=alert(1)>", "/search?q=test%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
    "/?ref=javascript:alert(1)", "/profile?name=<svg onload=alert(1)>",
    # Command Injection
    "/run?cmd=; whoami", "/api?q=test | cat /etc/passwd", "/run?cmd=; ls -la",
    "/shell?c=&& netstat -an", "/exec?command=id", "/api?x=$(id)",
    # Directory Traversal
    "/static/..%252f..%252f..%252fetc/passwd", "/view?path=..%2f..%2f..%2fetc%2fpasswd",
    "/download?file=../../../etc/passwd", r"/api/file?path=..\..\..\windows\system32\config\sam"
]

def generate_synthetic_data():
    data = []
    for url in BENIGN_URLS * 10: # Oversample
        data.append({"url": url, "label": "safe", "attack_type": "None"})
    
    for url in MALICIOUS_URLS * 5: # Oversample
        attack_type = "SQL Injection" if "OR" in url.upper() or "UNION" in url.upper() or "DROP" in url.upper() or "AND 1=1" in url.upper() else \
                      "XSS" if "<" in url or "script" in url.lower() or "alert" in url.lower() else \
                      "Command Injection" if "cmd=" in url or "cat" in url or "whoami" in url or "id" in url or "netstat" in url else \
                      "Directory Traversal"
        data.append({"url": url, "label": "malicious", "attack_type": attack_type})
        
    return pd.DataFrame(data)

def train_and_save_model():
    print("Loading/generating dataset...")
    df = generate_synthetic_data()
    
    X = df['url']
    # Target label: we'll predict the specific attack_type, and if it's "None", it's safe.
    y = df['attack_type']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Pipeline...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(1, 3))),
        ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    pipeline.fit(X_train, y_train)
    
    print("Evaluating Model...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save the model
    os.makedirs('models', exist_ok=True)
    model_path = os.path.join('models', 'url_detector_model.pkl')
    joblib.dump(pipeline, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_and_save_model()
