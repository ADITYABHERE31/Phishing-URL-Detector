import joblib
from feature_extractor import extract_features

model = joblib.load("ml/phishing_model.pkl")

url = "https://www.google.com/"
features = extract_features(url)

prediction = model.predict([list(features.values())])
probability = model.predict_proba([list(features.values())])

print("Prediction:", prediction[0])
print("Probability:", probability[0])

if prediction[0] == 0:
    print("Phishing URL")
else:
    print("Legitimate URL")