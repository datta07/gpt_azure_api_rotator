from fastapi import FastAPI, HTTPException, Body
import sqlite3
from typing import Dict, List
from datetime import datetime, timedelta
import requests
from Crypto.Cipher import AES  # Use pycryptodome for AES encryption
from Crypto.Util.Padding import unpad
import base64
import json
import os

app = FastAPI()

# AES Configuration
SECRET_KEY = os.environ.get('AES_SECRET_KEY').encode('utf-8')  # Must be 32 bytes for AES-256
IV = os.environ.get('AES_IV').encode('utf-8')  # Initialization vector (16 bytes)

# Telegram Configuration
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')

# Mock API keys and models
API_KEYS: Dict[str, str] = json.loads(os.environ.get('API_KEYS'))
MODELS: List[str] = json.loads(os.environ.get('MODELS'))


# Database setup
DATABASE = "api_usage.db"

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage (
                api_key TEXT,
                model TEXT,
                count INTEGER DEFAULT 0,
                last_reset DATETIME,
                is_rate_limited BOOLEAN DEFAULT FALSE,
                PRIMARY KEY (api_key, model)
            )
        ''')
        conn.commit()

init_db()

    # Dummy function to notify change
def notify_change(model: str, api_key: str, label: str):
    # Send a Telegram message to notify change
    telegram_api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    chat_id = TELEGRAM_CHAT_ID
    message = f"Switched to model {model} using API with label {label}"
    print(message)
    
    response = requests.post(telegram_api_url, data={
        'chat_id': chat_id,
        'text': message
    })
    response.raise_for_status()  # Raise an exception if the request failed
def reset_daily_limits_if_needed(api_key: str, model: str):
    """Reset the usage count if the last reset was more than a day ago for the specific API key and model."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT last_reset FROM usage
            WHERE api_key = ? AND model = ?
        ''', (api_key, model))
        result = cursor.fetchone()
        if result and result[0]:
            last_reset = datetime.fromisoformat(result[0])
            if datetime.now() - last_reset > timedelta(days=1):
                cursor.execute('''
                    UPDATE usage
                    SET count = 0, last_reset = ?, is_rate_limited = FALSE
                    WHERE api_key = ? AND model = ?
                ''', (datetime.now().isoformat(), api_key, model))
                conn.commit()

def get_next_api_key_model():
    """Get the next available API key and model combination."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        for model in MODELS:
            for api_key, label in API_KEYS.items():
                reset_daily_limits_if_needed(api_key, model)  # Reset limits if needed for this key and model
                cursor.execute('''
                    SELECT count, is_rate_limited FROM usage
                    WHERE api_key = ? AND model = ?
                ''', (api_key, model))
                result = cursor.fetchone()
                if not result or (not result[1]):  # Check count and rate-limit status result[0] < 50
                    if not result:
                        cursor.execute('''
                            INSERT INTO usage (api_key, model, count, last_reset, is_rate_limited)
                            VALUES (?, ?, 1, ?, FALSE)
                        ''', (api_key, model, datetime.now().isoformat()))
                        notify_change(model, api_key, label)
                    else:
                        # cursor.execute('''
                        #     UPDATE usage SET count = count + 1
                        #     WHERE api_key = ? AND model = ?
                        # ''', (api_key, model))
                        pass
                    conn.commit()
                    return api_key, model
        raise HTTPException(status_code=429, detail="API limit reached for all keys and models")

def mark_rate_limited(api_key: str, model: str):
    """Mark an API key and model combination as rate-limited."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE usage
            SET is_rate_limited = TRUE
            WHERE api_key = ? AND model = ?
        ''', (api_key, model))
        conn.commit()

def decrypt_data(encrypted_data: str) -> dict:
    """Decrypt the data using AES."""
    try:
        # Decode the base64-encoded encrypted data
        encrypted_bytes = base64.b64decode(encrypted_data)
        # Create AES cipher
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)
        # Decrypt the data
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        # Convert bytes to JSON
        decrypted_data = json.loads(decrypted_bytes.decode("utf-8"))
        return decrypted_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

def callRealAPI(api_key: str, model: str, payload: dict):
    """
    Calls the real API at https://model_re.com/0 with the provided API key, model, and payload.
    Returns the direct response from the API.
    """
    url = "https://models.inference.ai.azure.com/chat/completions"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}',
    }
    payload = {
        'messages': payload,  # Assumes messages have to_gpt_map method
        'temperature': 0.5,
        'top_p': 0.1,
        'max_tokens': 1000,
        'model': model
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        return response.json()  # Return the JSON response
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:  # Rate limit exceeded
            mark_rate_limited(api_key, model)  # Mark the key as rate-limited
            raise HTTPException(status_code=429, detail=f"Rate limit exceeded for API key {api_key} and model {model}")
        else:
            raise HTTPException(status_code=500, detail=f"Error calling real API: {str(e)}")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error calling real API: {str(e)}")

@app.post("/chat")
def call_api(encrypted_data=Body(...)):
    try:
        # Decrypt the data
        decrypted_data = decrypt_data(encrypted_data)
        # Get the next available API key and model
        api_key, model = get_next_api_key_model()
        # Call the real API with the decrypted payload
        response = callRealAPI(api_key, model, decrypted_data)
        return response
    except HTTPException as e:
        if e.status_code == 429:  # Rate limit exceeded
            # Retry with the next available API key and model
            try:
                api_key, model = get_next_api_key_model()
                response = callRealAPI(api_key, model, decrypted_data)
                return response
            except HTTPException as e:
                raise e  # Re-raise the exception if all keys are rate-limited
        else:
            raise e  # Re-raise other exceptions

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)