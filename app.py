import os
import json
import time
import threading
import secrets
import random
import base64
import re
import hashlib
from datetime import datetime, timedelta, UTC
from functools import wraps
from collections import defaultdict
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, abort, make_response
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# ------------------------- FILE PATHS (Vercel vs Local) -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_VERCEL = bool(os.environ.get('VERCEL'))

if IS_VERCEL:
    DB_PATH = os.path.join('/tmp', 'db.txt')
    SERVICES_PATH = os.path.join('/tmp', 'services.json')
    REQUEST_LOG_PATH = os.path.join('/tmp', 'request_log.txt')
else:
    DB_PATH = os.path.join(BASE_DIR, 'db.txt')
    SERVICES_PATH = os.path.join(BASE_DIR, 'services.json')
    REQUEST_LOG_PATH = os.path.join(BASE_DIR, 'request_log.txt')

DB_LOCK = threading.Lock()
SERVICES_LOCK = threading.Lock()

# ------------------------- CONFIGURATION -------------------------
BOT_TOKEN = '8096971691:AAGy5LsjFEoh3lnQnOubL_SSWYc4b-Rdtuc'
ADMIN_CHAT_ID = '7531333080'
ADMIN_DEPOSIT_PASSWORD = 'Khm3rT0pUp!2024#Secure'
ADMIN_SECRET_PATH = 'ff'
ADMIN_PASSWORD = 'aiden123'

TOPUP_CHAT_ID = os.getenv('TOPUP_CHAT_ID',7531333080)

# Geo-blocking: comma-separated country codes, e.g., "CN,RU,KP"
BLOCKED_COUNTRIES = os.getenv('BLOCKED_COUNTRIES', '').strip().upper().split(',')
GEO_BLOCK_ENABLED = bool(BLOCKED_COUNTRIES) and BLOCKED_COUNTRIES != ['']

# HTTP Basic Auth for admin secret paths (optional)
BASIC_AUTH_USER = os.getenv('BASIC_AUTH_USER', '')
BASIC_AUTH_PASS = os.getenv('BASIC_AUTH_PASS', '')
BASIC_AUTH_ENABLED = bool(BASIC_AUTH_USER and BASIC_AUTH_PASS)

# Rate limits
REQUEST_THRESHOLD = int(os.getenv('REQ_LIMIT', 20))          # requests/min for web pages
API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', 30))        # requests/min for API
LOGIN_RATE_LIMIT = 5                                          # max login attempts per 15 min
LOGIN_RATE_WINDOW = 900                                       # 15 minutes in seconds

# Request size limit (overall)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB

# ------------------------- RATE LIMITING STORAGE -------------------------
request_counts = defaultdict(list)
api_request_counts = defaultdict(list)
login_attempts = defaultdict(list)  # For login brute-force protection

def log_request(ip, is_api=False):
    now = time.time()
    if is_api:
        api_request_counts[ip].append(now)
        api_request_counts[ip] = [t for t in api_request_counts[ip] if now - t < 60]
        return len(api_request_counts[ip])
    else:
        request_counts[ip].append(now)
        request_counts[ip] = [t for t in request_counts[ip] if now - t < 60]
        try:
            with open(REQUEST_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now(UTC).isoformat()} | {ip}\n")
        except (PermissionError, OSError):
            pass
        return len(request_counts[ip])

def check_login_rate(ip):
    now = time.time()
    window = LOGIN_RATE_WINDOW
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]
    return len(login_attempts[ip])

def record_login_attempt(ip):
    login_attempts[ip].append(time.time())

# ------------------------- SESSION CONFIG -------------------------
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = IS_VERCEL
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'សូមចូលគណនីដើម្បីបន្ត។'
login_manager.remember_cookie_duration = timedelta(days=30)
login_manager.session_protection = "strong"

# ------------------------- SECURITY HEADERS -------------------------
@app.after_request
def add_security_headers(response):
    # Content-Security-Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    # HSTS (only on HTTPS)
    if IS_VERCEL:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'DENY'
    # Cross-site scripting filter (legacy)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Permissions Policy
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # Cross-domain policy
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    return response

# ------------------------- FILE HELPERS -------------------------
def read_json(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default if default is not None else {}

def write_json(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except (PermissionError, OSError) as e:
        print(f"Error writing to {path}: {e}")

def read_db():
    with DB_LOCK:
        return read_json(DB_PATH, default={
            'users': [],
            'deposits': [],
            'orders': [],
            'settings': {
                'maintenance_mode': False,
                'maintenance_key': secrets.token_hex(8),
                'admin_secret_path': ADMIN_SECRET_PATH
            }
        })

def write_db(data):
    with DB_LOCK:
        write_json(DB_PATH, data)

def read_services():
    with SERVICES_LOCK:
        return read_json(SERVICES_PATH, default=[])

def write_services(services):
    with SERVICES_LOCK:
        write_json(SERVICES_PATH, services)

# ------------------------- DEFAULT SERVICES -------------------------
DEFAULT_SERVICES = [
    # MOBILE LEGEND PH
    {"game": "mlbb_ph", "product": "50x2PH", "price": 1.15, "command": "/mlbbph {uid} {server_id} 50x2PH", "needs_server": True},
    {"game": "mlbb_ph", "product": "150x2PH", "price": 3.33, "command": "/mlbbph {uid} {server_id} 150x2PH", "needs_server": True},
    {"game": "mlbb_ph", "product": "250x2PH", "price": 5.47, "command": "/mlbbph {uid} {server_id} 250x2PH", "needs_server": True},
    {"game": "mlbb_ph", "product": "500x2PH", "price": 11.22, "command": "/mlbbph {uid} {server_id} 500x2PH", "needs_server": True},
    {"game": "mlbb_ph", "product": "11", "price": 0.19, "command": "/mlbbph {uid} {server_id} 11", "needs_server": True},
    {"game": "mlbb_ph", "product": "22", "price": 0.38, "command": "/mlbbph {uid} {server_id} 22", "needs_server": True},
    {"game": "mlbb_ph", "product": "56", "price": 0.86, "command": "/mlbbph {uid} {server_id} 56", "needs_server": True},
    {"game": "mlbb_ph", "product": "112", "price": 1.65, "command": "/mlbbph {uid} {server_id} 112", "needs_server": True},
    {"game": "mlbb_ph", "product": "223", "price": 3.20, "command": "/mlbbph {uid} {server_id} 223", "needs_server": True},
    {"game": "mlbb_ph", "product": "336", "price": 4.85, "command": "/mlbbph {uid} {server_id} 336", "needs_server": True},
    {"game": "mlbb_ph", "product": "570", "price": 8.08, "command": "/mlbbph {uid} {server_id} 570", "needs_server": True},
    {"game": "mlbb_ph", "product": "1163", "price": 16.35, "command": "/mlbbph {uid} {server_id} 1163", "needs_server": True},
    {"game": "mlbb_ph", "product": "2398", "price": 32.35, "command": "/mlbbph {uid} {server_id} 2398", "needs_server": True},
    {"game": "mlbb_ph", "product": "6042", "price": 78.35, "command": "/mlbbph {uid} {server_id} 6042", "needs_server": True},
    {"game": "mlbb_ph", "product": "wkp", "price": 1.59, "command": "/mlbbph {uid} {server_id} wkp", "needs_server": True},
    {"game": "mlbb_ph", "product": "TwilightPH", "price": 8.99, "command": "/mlbbph {uid} {server_id} TwilightPH", "needs_server": True},
    # MOBILE LEGEND INDONESIA
    {"game": "mlbb_id", "product": "500x2", "price": 9.99, "command": "/mlbbid {uid} {server_id} 500x2", "needs_server": True},
    {"game": "mlbb_id", "product": "150x2", "price": 3.30, "command": "/mlbbid {uid} {server_id} 150x2", "needs_server": True},
    {"game": "mlbb_id", "product": "50x2", "price": 1.20, "command": "/mlbbid {uid} {server_id} 50x2", "needs_server": True},
    {"game": "mlbb_id", "product": "45", "price": 1.15, "command": "/mlbbid {uid} {server_id} 45", "needs_server": True},
    {"game": "mlbb_id", "product": "33", "price": 6.50, "command": "/mlbbid {uid} {server_id} 33", "needs_server": True},
    {"game": "mlbb_id", "product": "5", "price": 0.15, "command": "/mlbbid {uid} {server_id} 5", "needs_server": True},
    {"game": "mlbb_id", "product": "12", "price": 0.30, "command": "/mlbbid {uid} {server_id} 12", "needs_server": True},
    {"game": "mlbb_id", "product": "19", "price": 0.45, "command": "/mlbbid {uid} {server_id} 19", "needs_server": True},
    {"game": "mlbb_id", "product": "28", "price": 0.69, "command": "/mlbbid {uid} {server_id} 28", "needs_server": True},
    {"game": "mlbb_id", "product": "44", "price": 0.89, "command": "/mlbbid {uid} {server_id} 44", "needs_server": True},
    {"game": "mlbb_id", "product": "59", "price": 1.10, "command": "/mlbbid {uid} {server_id} 59", "needs_server": True},
    {"game": "mlbb_id", "product": "85", "price": 1.49, "command": "/mlbbid {uid} {server_id} 85", "needs_server": True},
    {"game": "mlbb_id", "product": "170", "price": 2.99, "command": "/mlbbid {uid} {server_id} 170", "needs_server": True},
    {"game": "mlbb_id", "product": "240", "price": 3.99, "command": "/mlbbid {uid} {server_id} 240", "needs_server": True},
    {"game": "mlbb_id", "product": "296", "price": 4.99, "command": "/mlbbid {uid} {server_id} 296", "needs_server": True},
    {"game": "mlbb_id", "product": "408", "price": 6.99, "command": "/mlbbid {uid} {server_id} 408", "needs_server": True},
    {"game": "mlbb_id", "product": "568", "price": 9.69, "command": "/mlbbid {uid} {server_id} 568", "needs_server": True},
    {"game": "mlbb_id", "product": "875", "price": 13.99, "command": "/mlbbid {uid} {server_id} 875", "needs_server": True},
    {"game": "mlbb_id", "product": "2010", "price": 30.99, "command": "/mlbbid {uid} {server_id} 2010", "needs_server": True},
    {"game": "mlbb_id", "product": "4026", "price": 70.00, "command": "/mlbbid {uid} {server_id} 4026", "needs_server": True},
    {"game": "mlbb_id", "product": "758", "price": 14.30, "command": "/mlbbid {uid} {server_id} 758", "needs_server": True},
    {"game": "mlbb_id", "product": "CouponPass", "price": 4.88, "command": "/mlbbid {uid} {server_id} CouponPass", "needs_server": True},
    {"game": "mlbb_id", "product": "4830", "price": 72.00, "command": "/mlbbid {uid} {server_id} 4830", "needs_server": True},
    {"game": "mlbb_id", "product": "Weekly", "price": 1.90, "command": "/mlbbid {uid} {server_id} Weekly", "needs_server": True},
    {"game": "mlbb_id", "product": "Twilight", "price": 10.00, "command": "/mlbbid {uid} {server_id} Twilight", "needs_server": True},
    # MAGIC CHESS GOGO
    {"game": "mg", "product": "5", "price": 0.10, "command": "/mg {uid} {server_id} 5", "needs_server": True},
    {"game": "mg", "product": "11", "price": 0.18, "command": "/mg {uid} {server_id} 11", "needs_server": True},
    {"game": "mg", "product": "19", "price": 0.32, "command": "/mg {uid} {server_id} 19", "needs_server": True},
    {"game": "mg", "product": "28", "price": 0.50, "command": "/mg {uid} {server_id} 28", "needs_server": True},
    {"game": "mg", "product": "44", "price": 0.78, "command": "/mg {uid} {server_id} 44", "needs_server": True},
    {"game": "mg", "product": "59", "price": 0.99, "command": "/mg {uid} {server_id} 59", "needs_server": True},
    {"game": "mg", "product": "85", "price": 1.34, "command": "/mg {uid} {server_id} 85", "needs_server": True},
    {"game": "mg", "product": "170", "price": 2.68, "command": "/mg {uid} {server_id} 170", "needs_server": True},
    {"game": "mg", "product": "240", "price": 3.20, "command": "/mg {uid} {server_id} 240", "needs_server": True},
    {"game": "mg", "product": "257", "price": 3.85, "command": "/mg {uid} {server_id} 257", "needs_server": True},
    {"game": "mg", "product": "296", "price": 4.51, "command": "/mg {uid} {server_id} 296", "needs_server": True},
    {"game": "mg", "product": "408", "price": 6.32, "command": "/mg {uid} {server_id} 408", "needs_server": True},
    {"game": "mg", "product": "568", "price": 8.19, "command": "/mg {uid} {server_id} 568", "needs_server": True},
    {"game": "mg", "product": "875", "price": 13.30, "command": "/mg {uid} {server_id} 875", "needs_server": True},
    {"game": "mg", "product": "2010", "price": 29.99, "command": "/mg {uid} {server_id} 2010", "needs_server": True},
    {"game": "mg", "product": "4830", "price": 73.03, "command": "/mg {uid} {server_id} 4830", "needs_server": True},
    {"game": "mg", "product": "Weekly", "price": 1.76, "command": "/mg {uid} {server_id} Weekly", "needs_server": True},
    {"game": "mg", "product": "LukasBattle", "price": 0.83, "command": "/mg {uid} {server_id} LukasBattle", "needs_server": True},
    {"game": "mg", "product": "BattleDiscount", "price": 0.82, "command": "/mg {uid} {server_id} BattleDiscount", "needs_server": True},
    {"game": "mg", "product": "LancelotGift", "price": 0.96, "command": "/mg {uid} {server_id} LancelotGift", "needs_server": True},
    # FREE FIRE INDONESIA
    {"game": "ff_id", "product": "5", "price": 0.15, "command": "/ffid {uid} {server_id} 5", "needs_server": True},
    {"game": "ff_id", "product": "12", "price": 0.20, "command": "/ffid {uid} {server_id} 12", "needs_server": True},
    {"game": "ff_id", "product": "50", "price": 0.50, "command": "/ffid {uid} {server_id} 50", "needs_server": True},
    {"game": "ff_id", "product": "70", "price": 0.65, "command": "/ffid {uid} {server_id} 70", "needs_server": True},
    {"game": "ff_id", "product": "140", "price": 1.29, "command": "/ffid {uid} {server_id} 140", "needs_server": True},
    {"game": "ff_id", "product": "355", "price": 2.95, "command": "/ffid {uid} {server_id} 355", "needs_server": True},
    {"game": "ff_id", "product": "720", "price": 5.80, "command": "/ffid {uid} {server_id} 720", "needs_server": True},
    {"game": "ff_id", "product": "1450", "price": 11.49, "command": "/ffid {uid} {server_id} 1450", "needs_server": True},
    {"game": "ff_id", "product": "2180", "price": 17.29, "command": "/ffid {uid} {server_id} 2180", "needs_server": True},
    {"game": "ff_id", "product": "3640", "price": 30.00, "command": "/ffid {uid} {server_id} 3640", "needs_server": True},
    {"game": "ff_id", "product": "7290", "price": 57.00, "command": "/ffid {uid} {server_id} 7290", "needs_server": True},
    {"game": "ff_id", "product": "Weekly", "price": 1.99, "command": "/ffid {uid} {server_id} Weekly", "needs_server": True},
    {"game": "ff_id", "product": "Monthly", "price": 5.99, "command": "/ffid {uid} {server_id} Monthly", "needs_server": True},
    {"game": "ff_id", "product": "BPcard", "price": 2.99, "command": "/ffid {uid} {server_id} BPcard", "needs_server": True},
    # HONOR OF KING
    {"game": "hok", "product": "16", "price": 0.22, "command": "/hok {uid} 16", "needs_server": False},
    {"game": "hok", "product": "80", "price": 0.95, "command": "/hok {uid} 80", "needs_server": False},
    {"game": "hok", "product": "240", "price": 2.68, "command": "/hok {uid} 240", "needs_server": False},
    {"game": "hok", "product": "400", "price": 4.49, "command": "/hok {uid} 400", "needs_server": False},
    {"game": "hok", "product": "560", "price": 6.25, "command": "/hok {uid} 560", "needs_server": False},
    {"game": "hok", "product": "830", "price": 8.95, "command": "/hok {uid} 830", "needs_server": False},
    {"game": "hok", "product": "1245", "price": 12.99, "command": "/hok {uid} 1245", "needs_server": False},
    {"game": "hok", "product": "2508", "price": 25.99, "command": "/hok {uid} 2508", "needs_server": False},
    {"game": "hok", "product": "4180", "price": 43.25, "command": "/hok {uid} 4180", "needs_server": False},
    {"game": "hok", "product": "8360", "price": 86.50, "command": "/hok {uid} 8360", "needs_server": False},
    # PUBG MOBILE
    {"game": "pg", "product": "60", "price": 0.99, "command": "/pg {uid} 60", "needs_server": False},
    {"game": "pg", "product": "325", "price": 4.50, "command": "/pg {uid} 325", "needs_server": False},
    {"game": "pg", "product": "660", "price": 9.25, "command": "/pg {uid} 660", "needs_server": False},
    {"game": "pg", "product": "1800", "price": 22.29, "command": "/pg {uid} 1800", "needs_server": False},
    {"game": "pg", "product": "3850", "price": 44.49, "command": "/pg {uid} 3850", "needs_server": False},
    {"game": "pg", "product": "8100", "price": 88.29, "command": "/pg {uid} 8100", "needs_server": False},
    # FREE FIRE Vietnam
    {"game": "ff_vn", "product": "25", "price": 0.22, "command": "/ffvn {uid} {server_id} 25", "needs_server": True},
    {"game": "ff_vn", "product": "51", "price": 0.40, "command": "/ffvn {uid} {server_id} 51", "needs_server": True},
    {"game": "ff_vn", "product": "113", "price": 0.80, "command": "/ffvn {uid} {server_id} 113", "needs_server": True},
    {"game": "ff_vn", "product": "283", "price": 1.99, "command": "/ffvn {uid} {server_id} 283", "needs_server": True},
    {"game": "ff_vn", "product": "566", "price": 3.99, "command": "/ffvn {uid} {server_id} 566", "needs_server": True},
    {"game": "ff_vn", "product": "1132", "price": 7.99, "command": "/ffvn {uid} {server_id} 1132", "needs_server": True},
    {"game": "ff_vn", "product": "2830", "price": 19.99, "command": "/ffvn {uid} {server_id} 2830", "needs_server": True},
    {"game": "ff_vn", "product": "Weekly", "price": 2.09, "command": "/ffvn {uid} {server_id} Weekly", "needs_server": True},
    {"game": "ff_vn", "product": "WeeklyLite", "price": 0.55, "command": "/ffvn {uid} {server_id} WeeklyLite", "needs_server": True},
    {"game": "ff_vn", "product": "Monthly", "price": 8.99, "command": "/ffvn {uid} {server_id} Monthly", "needs_server": True},
    {"game": "ff_vn", "product": "LevelUpPass", "price": 2.09, "command": "/ffvn {uid} {server_id} LevelUpPass", "needs_server": True},
    {"game": "ff_vn", "product": "BPcard", "price": 2.29, "command": "/ffvn {uid} {server_id} BPcard", "needs_server": True},
    {"game": "ff_vn", "product": "Evo3D", "price": 0.60, "command": "/ffvn {uid} {server_id} Evo3D", "needs_server": True},
    {"game": "ff_vn", "product": "Evo7D", "price": 0.90, "command": "/ffvn {uid} {server_id} Evo7D", "needs_server": True},
    {"game": "ff_vn", "product": "Evo30D", "price": 2.35, "command": "/ffvn {uid} {server_id} Evo30D", "needs_server": True},
]

def populate_default_services():
    if not read_services():
        new_services = []
        for i, s in enumerate(DEFAULT_SERVICES, start=1):
            new_services.append({
                "id": i,
                "game": s["game"],
                "product": s["product"],
                "price": s["price"],
                "command": s["command"],
                "needs_server": s["needs_server"],
                "active": True
            })
        write_services(new_services)

# ------------------------- USER CLASS -------------------------
class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict['id']
        self.username = user_dict['username']
        self.email = user_dict['email']
        self.password_hash = user_dict['password_hash']
        self.balance = user_dict.get('balance', 0.0)
        self.api_key = user_dict.get('api_key')
        self.is_admin = user_dict.get('is_admin', False)
        self.is_banned = user_dict.get('is_banned', False)
        self.created_at = user_dict.get('created_at', '')

    @property
    def is_active(self):
        return not self.is_banned

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'balance': self.balance,
            'api_key': self.api_key,
            'is_admin': self.is_admin,
            'is_banned': self.is_banned,
            'created_at': self.created_at
        }

# ------------------------- USER QUERIES -------------------------
def get_user_by_id(user_id):
    db = read_db()
    for u in db['users']:
        if u['id'] == user_id:
            return User(u)
    return None

def get_user_by_username(username):
    db = read_db()
    for u in db['users']:
        if u['username'].lower() == username.lower():
            return User(u)
    return None

def get_user_by_email(email):
    db = read_db()
    for u in db['users']:
        if u['email'].lower() == email.lower():
            return User(u)
    return None

def get_user_by_api_key(api_key):
    db = read_db()
    for u in db['users']:
        if u.get('api_key') == api_key:
            return User(u)
    return None

def save_user(user):
    db = read_db()
    found = False
    for i, u in enumerate(db['users']):
        if u['id'] == user.id:
            db['users'][i] = user.to_dict()
            found = True
            break
    if not found:
        new_id = max([u['id'] for u in db['users']] + [0]) + 1
        user.id = new_id
        db['users'].append(user.to_dict())
    write_db(db)

# ------------------------- DEPOSIT / ORDER HELPERS -------------------------
def add_deposit(user_id, amount, transfer_name, proof_base64):
    db = read_db()
    dep_id = max([d['id'] for d in db['deposits']] + [0]) + 1
    dep = {
        'id': dep_id,
        'user_id': user_id,
        'amount': amount,
        'transfer_name': transfer_name,
        'proof_url': proof_base64,
        'status': 'pending',
        'telegram_message_id': None,
        'telegram_chat_id': None,
        'created_at': datetime.now(UTC).isoformat()
    }
    db['deposits'].append(dep)
    write_db(db)
    return dep

def update_deposit(dep_id, updates):
    db = read_db()
    for d in db['deposits']:
        if d['id'] == dep_id:
            d.update(updates)
            break
    write_db(db)

def get_deposit(dep_id):
    db = read_db()
    for d in db['deposits']:
        if d['id'] == dep_id:
            return d
    return None

def add_order(user_id, service, uid, server_id):
    db = read_db()
    order_id = max([o['id'] for o in db['orders']] + [0]) + 1
    cmd = service['command']
    if service.get('needs_server', False):
        cmd = cmd.format(uid=uid, server_id=server_id)
    else:
        cmd = cmd.format(uid=uid)
    order = {
        'id': order_id,
        'user_id': user_id,
        'service_id': service.get('id'),
        'game': service['game'],
        'product': service['product'],
        'price': service['price'],
        'uid': uid,
        'server_id': server_id,
        'command': cmd,
        'status': 'pending',
        'created_at': datetime.now(UTC).isoformat()
    }
    db['orders'].append(order)
    write_db(db)
    return order

def get_orders_by_user(user_id, limit=None):
    db = read_db()
    orders = [o for o in db['orders'] if o['user_id'] == user_id]
    orders.sort(key=lambda x: x['id'], reverse=True)
    if limit:
        return orders[:limit]
    return orders

def get_deposits_by_user(user_id, limit=None):
    db = read_db()
    deps = [d for d in db['deposits'] if d['user_id'] == user_id]
    deps.sort(key=lambda x: x['id'], reverse=True)
    if limit:
        return deps[:limit]
    return deps

# ------------------------- TELEGRAM HELPERS -------------------------
def send_telegram(chat_id, text, reply_markup=None):
    if not BOT_TOKEN:
        return None
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}
    if reply_markup:
        payload['reply_markup'] = json.dumps(reply_markup)
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.json()
    except Exception as e:
        print('Telegram error:', e)
        return None

def edit_telegram_message(chat_id, message_id, text):
    if not BOT_TOKEN:
        return
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/editMessageText'
    payload = {'chat_id': chat_id, 'message_id': message_id, 'text': text, 'parse_mode': 'HTML'}
    try:
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print('Telegram edit error:', e)

def answer_callback(callback_id, text=""):
    if not BOT_TOKEN:
        return
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery'
    payload = {'callback_query_id': callback_id, 'text': text}
    requests.post(url, json=payload, timeout=10)

# ------------------------- CAPTCHA GENERATION -------------------------
def generate_captcha():
    a = random.randint(1, 20)
    b = random.randint(1, 20)
    session['captcha_code'] = str(a + b)
    return f"{a} + {b} = ?"

# ------------------------- GEO-BLOCKING -------------------------
def get_client_country(ip):
    cf_country = request.headers.get('CF-IPCountry', '').strip()
    if cf_country:
        return cf_country.upper()
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('countryCode', '').upper()
    except Exception:
        pass
    return None

# ------------------------- BOT / WAF DETECTION -------------------------
BOT_UA_PATTERNS = [
    'python-requests', 'curl', 'wget', 'go-http-client', 'zgrab', 'nikto',
    'sqlmap', 'nmap', 'masscan', 'netsparker', 'acunetix',
    'openvas', 'nessus', 'metasploit', 'dirbuster', 'burpsuite',
    'phantomjs', 'headless', 'selenium', 'puppeteer', 'postman',
]

def is_malicious_ua(user_agent):
    if not user_agent:
        return True
    ua_lower = user_agent.lower()
    for pattern in BOT_UA_PATTERNS:
        if pattern in ua_lower:
            return True
    return False

WAF_PATTERNS = [
    r'(%27|\')',
    r'(\bUNION\b.*\bSELECT\b)',
    r'(\bSELECT\b.*\bFROM\b)',
    r'(<script.*?>)',
    r'(javascript:)',
    r'(on\w+\s*=\s*".*?")',
    r'(%3Cscript%3E)',
    r'(../)',          # path traversal
    r'(\.\.%2f)',      # encoded path traversal
    r'(<.*?>)',        # generic HTML tags in input (XSS)
]

def check_waf(input_string):
    if not input_string:
        return False
    for pattern in WAF_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    return False

# ------------------------- BASIC AUTH DECORATOR -------------------------
def basic_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not BASIC_AUTH_ENABLED:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or auth.username != BASIC_AUTH_USER or auth.password != BASIC_AUTH_PASS:
            response = make_response('Unauthorized', 401)
            response.headers['WWW-Authenticate'] = 'Basic realm="Admin Area"'
            return response
        return f(*args, **kwargs)
    return decorated

# ------------------------- SESSION FINGERPRINTING -------------------------
def get_session_fingerprint():
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    return hashlib.sha256(f"{ip}:{ua}".encode()).hexdigest()

def is_valid_session_fingerprint():
    if 'fingerprint' not in session:
        return False
    return session.get('fingerprint') == get_session_fingerprint()

# ------------------------- CSRF -------------------------
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def csrf_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('_csrf_token')
            if not token or token != session.get('_csrf_token'):
                abort(403)
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ------------------------- MIDDLEWARE: GLOBAL SECURITY -------------------------
@app.before_request
def before_request():
    if request.path.startswith('/static'):
        return

    ip = get_client_ip()

    # Geo-blocking
    if GEO_BLOCK_ENABLED:
        country = get_client_country(ip)
        if country and country in BLOCKED_COUNTRIES:
            abort(403)

    # Bot detection
    ua = request.headers.get('User-Agent', '')
    if is_malicious_ua(ua):
        abort(403)

    # WAF on query string and body (if form)
    if check_waf(request.query_string.decode('utf-8', errors='ignore')):
        abort(403)
    if request.form and check_waf(json.dumps(dict(request.form), default=str)):
        abort(403)

    # Maintenance mode
    db = read_db()
    if db['settings'].get('maintenance_mode', False):
        if request.path != '/maintenance' and not request.path.startswith(f'/{ADMIN_SECRET_PATH}'):
            return render_template('maintenance.html'), 503

    # Rate limiting for web pages
    if not request.path.startswith('/api/'):
        count = log_request(ip)
        if count > REQUEST_THRESHOLD and request.path not in ['/captcha', '/verify-captcha']:
            if not session.get('captcha_verified'):
                return redirect(url_for('captcha_page'))

    # Session fingerprint check for authenticated users (exclude login/register/logout)
    if current_user.is_authenticated and request.endpoint not in ['login', 'register', 'logout', 'static']:
        if not is_valid_session_fingerprint():
            logout_user()
            flash('ផ្ទៀងផ្ទាត់សម័យមិនបានសម្រេច។ សូមចូលគណនីម្តងទៀត។', 'danger')
            return redirect(url_for('login'))

def get_client_ip():
    if IS_VERCEL:
        return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    return request.remote_addr

# ------------------------- MAIN ROUTES -------------------------
@app.route('/')
def index():
    services = read_services()
    return render_template('index.html', services=services)

@app.route('/captcha')
def captcha_page():
    question = generate_captcha()
    return render_template('captcha.html', question=question)

@app.route('/verify-captcha', methods=['POST'])
@csrf_required
def verify_captcha():
    answer = request.form.get('answer', '').strip()
    if answer == session.get('captcha_code'):
        session['captcha_verified'] = True
        session.permanent = True
        return redirect(url_for('index'))
    flash('កូដមិនត្រឹមត្រូវ', 'danger')
    return redirect(url_for('captcha_page'))

@app.route('/login', methods=['GET', 'POST'])
@csrf_required
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    ip = get_client_ip()
    if request.method == 'POST':
        # Login rate limiting
        if check_login_rate(ip) >= LOGIN_RATE_LIMIT:
            flash('ការព្យាយាមចូលច្រើនពេក។ សូមព្យាយាមម្តងទៀតនៅពេលក្រោយ។', 'danger')
            return redirect(url_for('login'))
        record_login_attempt(ip)

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        user = get_user_by_username(username)
        if not user or not check_password_hash(user.password_hash, password):
            flash('ឈ្មោះឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ', 'danger')
            return redirect(url_for('login'))
        if user.is_banned:
            flash('គណនីត្រូវបានហាមឃាត់', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=remember)
        session.permanent = True
        # Set session fingerprint
        session['fingerprint'] = get_session_fingerprint()
        flash('ចូលគណនីជោគជ័យ', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf_required
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Honeypot check
        honeypot = request.form.get('website', '')
        if honeypot:
            abort(403)  # likely a bot

        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('សូមបំពេញគ្រប់វាល', 'danger')
            return redirect(url_for('register'))
        if password != confirm:
            flash('ពាក្យសម្ងាត់មិនត្រូវគ្នា', 'danger')
            return redirect(url_for('register'))
        # Basic input validation
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
            flash('ឈ្មោះអ្នកប្រើអាចមានតែ a-z, 0-9, _ និងប្រវែង 3-30', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('អ៊ីមែលមិនត្រឹមត្រូវ', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('ពាក្យសម្ងាត់ត្រូវមានយ៉ាងហោចណាស់ 6 តួអក្សរ', 'danger')
            return redirect(url_for('register'))
        if check_waf(username) or check_waf(email):
            abort(403)

        if get_user_by_username(username) or get_user_by_email(email):
            flash('ឈ្មោះឬអ៊ីមែលមានរួចហើយ', 'danger')
            return redirect(url_for('register'))

        new_user = User({
            'id': 0,
            'username': username,
            'email': email,
            'password_hash': generate_password_hash(password),
            'balance': 0.0,
            'api_key': None,
            'is_admin': False,
            'is_banned': False,
            'created_at': datetime.now(UTC).isoformat()
        })
        save_user(new_user)
        if ADMIN_CHAT_ID:
            send_telegram(ADMIN_CHAT_ID, f"🆕 អ្នកប្រើថ្មី {username} ({email})")
        login_user(new_user)
        session.permanent = True
        session['fingerprint'] = get_session_fingerprint()
        flash('ចុះឈ្មោះជោគជ័យ', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', honeypot=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    recent_orders = get_orders_by_user(current_user.id, 5)
    deposits = get_deposits_by_user(current_user.id, 5)
    total_orders = len(get_orders_by_user(current_user.id))
    return render_template('dashboard.html',
                           recent_orders=recent_orders,
                           deposits=deposits,
                           total_orders=total_orders)

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
@csrf_required
def deposit():
    if request.method == 'POST':
        amount = request.form.get('amount', type=float)
        transfer_name = request.form.get('transfer_name', '').strip()
        file = request.files.get('proof_image')

        if not amount or amount <= 0:
            flash('ចំនួនទឹកប្រាក់មិនត្រឹមត្រូវ', 'danger')
            return redirect(url_for('deposit'))
        if not transfer_name:
            flash('សូមបំពេញឈ្មោះគណនីដែលបានផ្ទេរ', 'danger')
            return redirect(url_for('deposit'))
        if not file or file.filename == '':
            flash('សូមជ្រើសរើសឯកសាររូបភាព', 'danger')
            return redirect(url_for('deposit'))

        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in allowed_extensions:
            flash('ប្រភេទឯកសារមិនត្រូវបានអនុញ្ញាត។ សូមប្រើរូបភាព (PNG, JPG, GIF, WEBP)', 'danger')
            return redirect(url_for('deposit'))

        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0, 0)
        if file_length > 5 * 1024 * 1024:
            flash('ទំហំឯកសារធំពេក (អតិបរមា 5MB)', 'danger')
            return redirect(url_for('deposit'))

        # Sanitize transfer_name (prevent XSS)
        if check_waf(transfer_name):
            abort(403)

        image_data = base64.b64encode(file.read()).decode('utf-8')
        proof_base64 = f"data:image/{ext};base64,{image_data}"

        dep = add_deposit(current_user.id, amount, transfer_name, proof_base64)

        inline_keyboard = {
            "inline_keyboard": [[
                {"text": "✅ យល់ព្រម", "callback_data": f"accept_{dep['id']}"},
                {"text": "❌ បដិសេធ", "callback_data": f"reject_{dep['id']}"}
            ]]
        }
        msg_text = (
            f"💰 <b>ប្រាក់តម្កល់ថ្មី</b>\n"
            f"👤 {current_user.username}\n"
            f"💵 ${amount:.2f}\n"
            f"🏦 ឈ្មោះគណនីផ្ទេរ៖ {transfer_name}\n"
            f"🖼 ភស្តុតាង៖ បានផ្ទុករូបភាព\n"
            f"📌 ស្ថានភាព៖ កំពុងរងចាំ"
        )
        msg = send_telegram(ADMIN_CHAT_ID, msg_text, reply_markup=inline_keyboard)
        if msg and msg.get('ok'):
            update_deposit(dep['id'], {
                'telegram_message_id': msg['result']['message_id'],
                'telegram_chat_id': str(msg['result']['chat']['id'])
            })
        flash('សំណើដាក់ប្រាក់បានដាក់ស្នើ។ Admin នឹងពិនិត្យភស្តុតាង។', 'info')
        return redirect(url_for('dashboard'))
    return render_template('deposit.html')

@app.route('/order_history')
@login_required
def order_history():
    orders = get_orders_by_user(current_user.id)
    return render_template('order_history.html', orders=orders)

@app.route('/api/docs')
def api_docs():
    return render_template('api_docs.html')

@app.route('/api/order', methods=['POST'])
def api_order():
    ip = get_client_ip()
    api_count = log_request(ip, is_api=True)
    if api_count > API_RATE_LIMIT:
        return jsonify({"error": "Too many requests"}), 429

    api_key = request.headers.get('Authorization')
    if not api_key:
        return jsonify({"error": "Missing API key"}), 401
    user = get_user_by_api_key(api_key)
    if not user or user.is_banned:
        return jsonify({"error": "Invalid API key or banned"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    if check_waf(json.dumps(data)):
        return jsonify({"error": "Malicious input detected"}), 400

    game = data.get('game', '').strip().lower()
    product = data.get('product', '').strip()
    uid = str(data.get('uid', '')).strip()
    server_id = data.get('server_id')

    if check_waf(game) or check_waf(product) or check_waf(uid) or (server_id and check_waf(str(server_id))):
        return jsonify({"error": "Invalid input"}), 400

    services = read_services()
    service = next((s for s in services if s['game'] == game and s['product'] == product and s.get('active', True)), None)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    if service.get('needs_server') and not server_id:
        return jsonify({"error": "Server ID required"}), 400
    if user.balance < service['price']:
        return jsonify({"error": "Insufficient balance"}), 402

    user.balance -= service['price']
    save_user(user)
    order = add_order(user.id, service, uid, server_id)

    # Forward command to TOPUP bot
    if TOPUP_CHAT_ID:
        send_telegram(TOPUP_CHAT_ID, order['command'])

    if ADMIN_CHAT_ID:
        send_telegram(ADMIN_CHAT_ID, f"🛒 បញ្ជាទិញ\n👤 {user.username}\n🎮 {service['game']} | {service['product']}\n💰 ${service['price']:.2f}\n📟 {order['command']}")

    return jsonify({"status": "success", "order_id": order['id'], "command": order['command']})

@app.route('/generate_api_key', methods=['POST'])
@login_required
@csrf_required
def generate_api_key():
    if current_user.api_key:
        flash('អ្នកមាន API Key រួចហើយ', 'warning')
        return redirect(url_for('dashboard'))
    key = 'api_sk_' + secrets.token_hex(16)
    current_user.api_key = key
    save_user(current_user)
    flash('API Key បានបង្កើត', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reset_api_key', methods=['POST'])
@login_required
@csrf_required
def reset_api_key():
    key = 'api_sk_' + secrets.token_hex(16)
    current_user.api_key = key
    save_user(current_user)
    flash('API Key បានកំណត់ឡើងវិញ', 'success')
    return redirect(url_for('dashboard'))

# ------------------------- TELEGRAM WEBHOOK -------------------------
@app.route('/webhook/telegram', methods=['POST'])
def telegram_webhook():
    data = request.get_json()
    if not data or 'callback_query' not in data:
        return 'ok', 200
    cb = data['callback_query']
    cb_id = cb['id']
    cb_data = cb.get('data', '')
    msg = cb.get('message', {})
    chat_id = msg.get('chat', {}).get('id')
    message_id = msg.get('message_id')
    if cb_data.startswith('accept_') or cb_data.startswith('reject_'):
        action, dep_id_str = cb_data.split('_')
        dep_id = int(dep_id_str)
        dep = get_deposit(dep_id)
        if dep and dep['status'] == 'pending':
            user = get_user_by_id(dep['user_id'])
            if action == 'accept':
                dep['status'] = 'accepted'
                user.balance += dep['amount']
                save_user(user)
                update_deposit(dep_id, {'status': 'accepted'})
                edit_telegram_message(chat_id, message_id, f"✅ បានយល់ព្រម\n👤 {user.username}\n💵 ${dep['amount']:.2f}")
            else:
                update_deposit(dep_id, {'status': 'rejected'})
                edit_telegram_message(chat_id, message_id, f"❌ បានបដិសេធ\n👤 {user.username}\n💵 ${dep['amount']:.2f}")
        answer_callback(cb_id, "Done")
    return jsonify({"status": "ok"})

# ------------------------- HIDDEN ADMIN ROUTES -------------------------
@app.route(f'/{ADMIN_SECRET_PATH}', methods=['GET', 'POST'])
@basic_auth_required
def admin_login():
    if session.get('admin_authenticated'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            session.permanent = True
            return redirect(url_for('admin_dashboard'))
        flash('ពាក្យសម្ងាត់មិនត្រឹមត្រូវ', 'danger')
    return render_template('admin_login.html')

@app.route(f'/{ADMIN_SECRET_PATH}/dashboard')
@basic_auth_required
def admin_dashboard():
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login'))
    db = read_db()
    users = db['users']
    pending_deposits = [d for d in db['deposits'] if d['status'] == 'pending']
    orders = db['orders'][-20:]
    services = read_services()
    return render_template('admin.html',
                           users=users,
                           deposits=pending_deposits,
                           orders=orders,
                           services=services)

@app.route(f'/{ADMIN_SECRET_PATH}/services')
@basic_auth_required
def admin_services():
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login'))
    services = read_services()
    return render_template('admin_services.html', services=services)

@app.route(f'/{ADMIN_SECRET_PATH}/services/add', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_services_add():
    if not session.get('admin_authenticated'):
        abort(403)
    game = request.form.get('game', '').strip()
    product = request.form.get('product', '').strip()
    price = request.form.get('price', type=float)
    command = request.form.get('command', '').strip()
    needs_server = request.form.get('needs_server') == 'on'
    if not game or not product or price is None:
        flash('សូមបំពេញគ្រប់វាល', 'danger')
        return redirect(url_for('admin_services'))
    services = read_services()
    new_id = max([s['id'] for s in services] + [0]) + 1
    new_service = {
        'id': new_id,
        'game': game,
        'product': product,
        'price': price,
        'command': command,
        'needs_server': needs_server,
        'active': True
    }
    services.append(new_service)
    write_services(services)
    flash('បានបន្ថែមសេវាថ្មី', 'success')
    return redirect(url_for('admin_services'))

@app.route(f'/{ADMIN_SECRET_PATH}/services/edit/<int:service_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_services_edit(service_id):
    if not session.get('admin_authenticated'):
        abort(403)
    new_price = request.form.get('price', type=float)
    if new_price is None or new_price <= 0:
        flash('តម្លៃមិនត្រឹមត្រូវ', 'danger')
        return redirect(url_for('admin_services'))
    services = read_services()
    for s in services:
        if s['id'] == service_id:
            s['price'] = new_price
            break
    write_services(services)
    flash('តម្លៃបានធ្វើបច្ចុប្បន្នភាព', 'success')
    return redirect(url_for('admin_services'))

@app.route(f'/{ADMIN_SECRET_PATH}/services/delete/<int:service_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_services_delete(service_id):
    if not session.get('admin_authenticated'):
        abort(403)
    services = read_services()
    services = [s for s in services if s['id'] != service_id]
    write_services(services)
    flash('បានលុបសេវា', 'success')
    return redirect(url_for('admin_services'))

@app.route(f'/{ADMIN_SECRET_PATH}/services/toggle/<int:service_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_services_toggle(service_id):
    if not session.get('admin_authenticated'):
        abort(403)
    services = read_services()
    for s in services:
        if s['id'] == service_id:
            s['active'] = not s.get('active', True)
            break
    write_services(services)
    flash('បានផ្លាស់ប្ដូរស្ថានភាព', 'success')
    return redirect(url_for('admin_services'))

@app.route(f'/{ADMIN_SECRET_PATH}/deposits/approve/<int:dep_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_approve_deposit(dep_id):
    if not session.get('admin_authenticated'):
        abort(403)
    dep = get_deposit(dep_id)
    if not dep or dep['status'] != 'pending':
        flash('Deposit not found or already processed', 'warning')
        return redirect(url_for('admin_dashboard'))
    user = get_user_by_id(dep['user_id'])
    if not user:
        abort(404)
    user.balance += dep['amount']
    save_user(user)
    update_deposit(dep_id, {'status': 'accepted'})
    flash(f'បានយល់ព្រមការតម្កល់ #{dep_id} សម្រាប់ {user.username}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route(f'/{ADMIN_SECRET_PATH}/deposits/reject/<int:dep_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_reject_deposit(dep_id):
    if not session.get('admin_authenticated'):
        abort(403)
    update_deposit(dep_id, {'status': 'rejected'})
    flash(f'បានបដិសេធការតម្កល់ #{dep_id}', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route(f'/{ADMIN_SECRET_PATH}/users/ban/<int:user_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_ban_user(user_id):
    if not session.get('admin_authenticated'):
        abort(403)
    user = get_user_by_id(user_id)
    if user:
        user.is_banned = not user.is_banned
        save_user(user)
        flash(f'បាន{"ហាមឃាត់" if user.is_banned else "ដោះហាមឃាត់"} {user.username}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route(f'/{ADMIN_SECRET_PATH}/users/add_balance/<int:user_id>', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_add_balance(user_id):
    if not session.get('admin_authenticated'):
        abort(403)
    amount = request.form.get('amount', type=float)
    user = get_user_by_id(user_id)
    if user and amount:
        user.balance += amount
        save_user(user)
        flash(f'បានបន្ថែម ${amount:.2f} ទៅ {user.username}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route(f'/{ADMIN_SECRET_PATH}/maintenance', methods=['POST'])
@csrf_required
@basic_auth_required
def admin_maintenance():
    if not session.get('admin_authenticated'):
        abort(403)
    db = read_db()
    db['settings']['maintenance_mode'] = not db['settings'].get('maintenance_mode', False)
    write_db(db)
    flash('បានផ្លាស់ប្ដូររបៀបថែទាំ', 'success')
    return redirect(url_for('admin_dashboard'))

# ------------------------- SEPARATE DEPOSIT CONFIRMATION (Public admin) -------------------------
@app.route('/admin/deposits', methods=['GET', 'POST'])
@csrf_required
def public_deposit_admin():
    if not session.get('deposit_admin_authenticated'):
        if request.method == 'POST':
            pwd = request.form.get('password')
            if pwd == ADMIN_DEPOSIT_PASSWORD:
                session['deposit_admin_authenticated'] = True
                session.permanent = True
                return redirect(url_for('public_deposit_admin'))
            flash('ពាក្យសម្ងាត់មិនត្រឹមត្រូវ', 'danger')
        return render_template('deposit_admin_login.html')
    pending_deps = [d for d in read_db()['deposits'] if d['status'] == 'pending']
    return render_template('admin_deposits.html', deposits=pending_deps)

@app.route('/admin/deposits/approve/<int:dep_id>', methods=['POST'])
@csrf_required
def public_approve_deposit(dep_id):
    if not session.get('deposit_admin_authenticated'):
        abort(403)
    dep = get_deposit(dep_id)
    if dep and dep['status'] == 'pending':
        user = get_user_by_id(dep['user_id'])
        user.balance += dep['amount']
        save_user(user)
        update_deposit(dep_id, {'status': 'accepted'})
        flash('បានយល់ព្រម', 'success')
    return redirect(url_for('public_deposit_admin'))

@app.route('/admin/deposits/reject/<int:dep_id>', methods=['POST'])
@csrf_required
def public_reject_deposit(dep_id):
    if not session.get('deposit_admin_authenticated'):
        abort(403)
    update_deposit(dep_id, {'status': 'rejected'})
    flash('បានបដិសេធ', 'info')
    return redirect(url_for('public_deposit_admin'))

# ------------------------- MAINTENANCE PAGE -------------------------
@app.route('/maintenance')
def maintenance():
    return render_template('maintenance.html')

# ------------------------- INITIALIZATION -------------------------
with app.app_context():
    read_db()
    populate_default_services()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
