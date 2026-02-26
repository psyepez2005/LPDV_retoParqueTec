import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

def train():
    print("[1] Cargando el dataset de 5000 registros...")
    df = pd.read_csv("data/dataset.csv")

    # 13 variables estratégicas: Dinero, Comportamiento y Entorno
    features = [
        'amount', 
        'account_age_days', 
        'failed_tx_last_7_days', 
        'form_fill_time_seconds', 
        'paste_count', 
        'is_vpn_or_proxy',
        'is_international_card',
        'is_rooted_device',
        'is_emulator',
        'tx_count_last_30_days',
        'device_tx_last_24h',
        'time_since_last_tx_minutes',
        'session_duration_seconds'
    ]
    
    X = df[features]
    y = df['is_fraud'] 

    print("[2] Dividiendo datos (80% entrenamiento / 20% examen)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[3] Entrenando el modelo Random Forest...")
    # class_weight="balanced" es muy importante para que no ignore los casos de fraude si son pocos
    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    score = clf.score(X_test, y_test)
    print(f"[4] Entrenamiento completado. Precisión en el examen: {score * 100:.2f}%")

    print("[5] Guardando el modelo entrenado...")
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, "models/fraud_model.pkl")
    print("¡Éxito! El modelo está guardado en models/fraud_model.pkl")

if __name__ == "__main__":
    train()