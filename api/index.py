from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import secrets
from supabase import create_client, Client
from datetime import datetime, timedelta
import jwt
import re

app = Flask(__name__)
CORS(app)

# Supabase-Konfiguration (BITTE ERSETZEN SIE DIESE MIT IHREN ECHTEN DATEN)
SUPABASE_URL = "https://pqvvkqjhfwqjxqxqxqxq.supabase.co"
SUPABASE_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBxdnZrcWpoZndxanhxeHF4cXhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjM2MzY4NzQsImV4cCI6MjAzOTIxMjg3NH0.example"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY )

# JWT-Konfiguration
JWT_SECRET = "zyrix-jwt-secret-key-2024"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_jwt_token(user_id, email):
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/')
def home():
    return jsonify({
        "message": "Zyrix Backend API",
        "version": "2.0",
        "status": "online",
        "endpoints": [
            "/api/register",
            "/api/login",
            "/api/request-password-reset",
            "/api/reset-password"
        ]
    })

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        required_fields = ['full_name', 'email', 'password', 'strasse', 'plz', 'stadt', 'land']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Feld {field} ist erforderlich'}), 400

        if not validate_email(data['email']):
            return jsonify({'error': 'Ungültige E-Mail-Adresse'}), 400

        if len(data['password']) < 8:
            return jsonify({'error': 'Passwort muss mindestens 8 Zeichen lang sein'}), 400

        existing_user = supabase.table('users').select('*').eq('email', data['email']).execute()
        if existing_user.data:
            return jsonify({'error': 'E-Mail-Adresse bereits registriert'}), 400

        hashed_password = hash_password(data['password'])

        user_data = {
            'full_name': data['full_name'],
            'email': data['email'],
            'password_hash': hashed_password,
            'strasse': data['strasse'],
            'plz': data['plz'],
            'stadt': data['stadt'],
            'land': data['land'],
            'firmenname': data.get('firmenname'),
            'ust_idnr': data.get('ust_idnr'),
            'tokens': 1200,
            'tokens_expires_at': (datetime.utcnow() + timedelta(days=7)).isoformat(),
            'created_at': datetime.utcnow().isoformat()
        }

        result = supabase.table('users').insert(user_data).execute()

        if result.data:
            user = result.data[0]
            return jsonify({
                'message': 'Registrierung erfolgreich',
                'user_id': user['id'],
                'tokens': user['tokens'],
                'tokens_expires_at': user['tokens_expires_at']
            }), 201
        else:
            return jsonify({'error': 'Fehler beim Erstellen des Benutzers'}), 500

    except Exception as e:
        return jsonify({'error': f'Server-Fehler: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'E-Mail und Passwort sind erforderlich'}), 400

        user_result = supabase.table('users').select('*').eq('email', data['email']).execute()

        if not user_result.data:
            return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

        user = user_result.data[0]

        if hash_password(data['password']) != user['password_hash']:
            return jsonify({'error': 'Ungültige Anmeldedaten'}), 401

        token = generate_jwt_token(user['id'], user['email'])

        return jsonify({
            'message': 'Anmeldung erfolgreich',
            'token': token,
            'user': {
                'id': user['id'],
                'full_name': user['full_name'],
                'email': user['email'],
                'tokens': user['tokens'],
                'tokens_expires_at': user['tokens_expires_at']
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Server-Fehler: {str(e)}'}), 500

@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    try:
        data = request.get_json()

        if not data.get('email'):
            return jsonify({'error': 'E-Mail-Adresse ist erforderlich'}), 400

        user_result = supabase.table('users').select('*').eq('email', data['email']).execute()

        if not user_result.data:
            return jsonify({'message': 'Falls die E-Mail-Adresse existiert, wurde ein Reset-Link gesendet'}), 200

        user = user_result.data[0]

        reset_token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)

        supabase.table('password_resets').insert({
            'user_id': user['id'],
            'token': reset_token,
            'expires_at': expires_at.isoformat(),
            'used': False
        }).execute()

        reset_link = f"https://zyrix-tool1.vercel.app/reset-password.html?token={reset_token}"

        return jsonify({
            'message': 'Reset-Link wurde gesendet',
            'reset_link': reset_link
        } ), 200

    except Exception as e:
        return jsonify({'error': f'Server-Fehler: {str(e)}'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()

        if not data.get('token') or not data.get('new_password'):
            return jsonify({'error': 'Token und neues Passwort sind erforderlich'}), 400

        reset_result = supabase.table('password_resets').select('*').eq('token', data['token']).eq('used', False).execute()

        if not reset_result.data:
            return jsonify({'error': 'Ungültiger oder abgelaufener Reset-Token'}), 400

        reset_record = reset_result.data[0]

        expires_at = datetime.fromisoformat(reset_record['expires_at'].replace('Z', '+00:00'))
        if datetime.utcnow().replace(tzinfo=expires_at.tzinfo) > expires_at:
            return jsonify({'error': 'Reset-Token ist abgelaufen'}), 400

        if len(data['new_password']) < 8:
            return jsonify({'error': 'Passwort muss mindestens 8 Zeichen lang sein'}), 400

        new_password_hash = hash_password(data['new_password'])
        supabase.table('users').update({
            'password_hash': new_password_hash
        }).eq('id', reset_record['user_id']).execute()

        supabase.table('password_resets').update({
            'used': True
        }).eq('id', reset_record['id']).execute()

        return jsonify({'message': 'Passwort erfolgreich geändert'}), 200

    except Exception as e:
        return jsonify({'error': f'Server-Fehler: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
