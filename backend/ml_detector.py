import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'url_detector_model.pkl')
model = None

def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
        except Exception as e:
            print(f"Error loading ML model: {e}")
    else:
        print(f"Warning: ML model not found at {MODEL_PATH}. Run train_model.py first.")

def predict_attack(url: str):
    """
    Predicts if a URL is malicious using the trained ML model.
    Returns:
        dict with attack_type and confidence_score, or None if safe/model not loaded.
    """
    global model
    if model is None:
        load_model()
    
    if model is None:
        return None # Model still not loaded
        
    try:
        prediction = model.predict([url])[0]
        if prediction == "None" or prediction == "safe":
            return None # Safe
            
        # Get probability/confidence
        probabilities = model.predict_proba([url])[0]
        confidence = int(max(probabilities) * 100)
        
        return {
            "attack_type": prediction,
            "confidence_score": confidence,
            "is_anomalous": confidence > 80 # Simple anomaly flag
        }
    except Exception as e:
        print(f"ML Prediction error: {e}")
        return None
