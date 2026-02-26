from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import os

app = FastAPI(title="Microservicio ML Antifraude - Plux")

# Carga del modelo en memoria al iniciar el servidor
MODEL_PATH = "models/fraud_model.pkl"
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print("Modelo de Machine Learning cargado en memoria.")
else:
    model = None
    print("ADVERTENCIA: No hay modelo. Debes ejecutar train_model.py primero.")

# El esquema estricto con las 13 variables
class MLTransactionPayload(BaseModel):
    amount: float
    account_age_days: int
    failed_tx_last_7_days: int
    form_fill_time_seconds: int
    paste_count: int
    is_vpn_or_proxy: bool
    is_international_card: bool
    is_rooted_device: bool
    is_emulator: bool
    tx_count_last_30_days: int
    device_tx_last_24h: int
    time_since_last_tx_minutes: int
    session_duration_seconds: int

@app.post("/predict")
async def predict_fraud(payload: MLTransactionPayload):
    if model is None:
        raise HTTPException(status_code=500, detail="El modelo no está entrenado o no se encuentra el archivo .pkl")

    # IMPORTANTE: Scikit-Learn exige que las columnas estén en el mismo orden exacto 
    # en el que fueron entrenadas. 
    # Va el orden de la lista 'features'.
    input_data = pd.DataFrame([{
        "amount": payload.amount,
        "account_age_days": payload.account_age_days,
        "failed_tx_last_7_days": payload.failed_tx_last_7_days,
        "form_fill_time_seconds": payload.form_fill_time_seconds,
        "paste_count": payload.paste_count,
        "is_vpn_or_proxy": payload.is_vpn_or_proxy,
        "is_international_card": payload.is_international_card,
        "is_rooted_device": payload.is_rooted_device,
        "is_emulator": payload.is_emulator,
        "tx_count_last_30_days": payload.tx_count_last_30_days,
        "device_tx_last_24h": payload.device_tx_last_24h,
        "time_since_last_tx_minutes": payload.time_since_last_tx_minutes,
        "session_duration_seconds": payload.session_duration_seconds
    }])

    # Calculamos la probabilidad (devuelve un array, tomamos el valor del índice 1 que es "fraude")
    probability = model.predict_proba(input_data)[0][1] 
    
    return {
        "status": "success",
        "fraud_probability": round(probability, 4),
        "is_fraud_flag": bool(probability > 0.75) # Umbral estricto del 75%
    }