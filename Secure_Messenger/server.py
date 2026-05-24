from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import json
import base64
import threading
import time
import hmac
import hashlib
import uuid
from datetime import datetime
from crypto import (load_dh_parameters, generate_dh_keypair, serialize_public_key,
                    deserialize_public_key, derive_shared_key, encrypt_message, decrypt_message)
import jwt
import datetime as dt

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # FIX: enables browser clients to reach the API

# FIX: Use a fixed SECRET_KEY so JWTs stay valid across restarts.
# os.urandom(24) regenerated on every restart, invalidating all tokens.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_messenger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# FIX: Fixed DAILY_SECRET so pseudonyms are stable across restarts.
app.config['DAILY_SECRET'] = os.environ.get('DAILY_SECRET', 'dev-daily-secret-change-in-production')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ── DH Parameters ─────────────────────────────────────────────────────────────
DH_PARAMETERS = load_dh_parameters()

# ── In-memory DHT ────────────────────────────────────────────────────────────
DHT = {}
DHT_LOCK = threading.Lock()

# ── Models ───────────────────────────────────────────────────────────────────
class User(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(80),  unique=True, nullable=False)
    pseudonym    = db.Column(db.String(120), unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password_hash= db.Column(db.String(128))
    public_key   = db.Column(db.Text)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {'id': self.id, 'username': self.username,
                'pseudonym': self.pseudonym, 'email': self.email}


class OfflineMessage(db.Model):
    id                   = db.Column(db.Integer, primary_key=True)
    recipient_pseudonym  = db.Column(db.String(120), nullable=False)
    sender_pseudonym     = db.Column(db.String(120), nullable=False)
    encrypted_message    = db.Column(db.Text)
    timestamp            = db.Column(db.DateTime, default=datetime.utcnow)


with app.app_context():
    db.create_all()

# ── Helpers ──────────────────────────────────────────────────────────────────
def generate_pseudonym(user_id):
    """HMAC-based pseudonym — stable for the same user_id + daily_secret."""
    daily_secret = app.config['DAILY_SECRET']
    # FIX: was hmac.new(...) which is correct but used wrong API style.
    # hmac.new is valid; we keep it and ensure bytes inputs.
    mac = hmac.new(
        daily_secret.encode('utf-8'),
        str(user_id).encode('utf-8'),
        hashlib.sha256
    )
    return mac.hexdigest()[:16]


def decode_token(auth_header):
    """Return user_id from Bearer token, or raise ValueError."""
    if not auth_header:
        raise ValueError('Missing token')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else auth_header
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return data['user_id']
    except jwt.PyJWTError as e:
        raise ValueError(f'Invalid token: {e}')


# ── Web UI route ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


# ── API: Auth ─────────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email')    or '').strip()
    password =  data.get('password') or ''

    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    # Temp pseudonym so NOT NULL constraint is satisfied before flush
    new_user = User(username=username, email=email, pseudonym=str(uuid.uuid4())[:16])
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.flush()                           # get the auto-assigned id
    new_user.pseudonym = generate_pseudonym(new_user.id)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'user_id': new_user.id}), 201


@app.route('/login', methods=['POST'])
def login():
    data     = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not (user and user.check_password(password)):
        return jsonify({'message': 'Invalid credentials'}), 401

    # FIX: PyJWT ≥ 2.0 returns str, not bytes — no .decode() needed.
    token = jwt.encode(
        {'user_id': user.id, 'exp': dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({'token': token, 'pseudonym': user.pseudonym,
                    'user_id': user.id, 'username': user.username}), 200


# ── API: Keys & DHT ───────────────────────────────────────────────────────────
@app.route('/publish_key', methods=['POST'])
def publish_key():
    try:
        user_id = decode_token(request.headers.get('Authorization'))
    except ValueError as e:
        return jsonify({'message': str(e)}), 401

    user = db.session.get(User, user_id)   # FIX: Query.get() deprecated in SQLAlchemy 2.x
    if not user:
        return jsonify({'message': 'User not found'}), 404

    body = request.get_json() or {}
    public_key_pem = body.get('public_key')
    if not public_key_pem:
        return jsonify({'message': 'Missing public key'}), 400

    user.public_key = public_key_pem
    db.session.commit()

    with DHT_LOCK:
        DHT[user.pseudonym] = {
            'ip': request.remote_addr,
            'port': 5000 + user_id,
            'public_key': public_key_pem,
            'last_seen': time.time()
        }

    return jsonify({'message': 'Public key published', 'pseudonym': user.pseudonym}), 200


@app.route('/get_user/<pseudonym>', methods=['GET'])
def get_user(pseudonym):
    with DHT_LOCK:
        info = DHT.get(pseudonym)
    if info:
        return jsonify(info), 200
    # Fallback: check DB for stored public key (survives server restarts)
    user = User.query.filter_by(pseudonym=pseudonym).first()
    if user and user.public_key:
        return jsonify({'public_key': user.public_key, 'ip': None, 'port': None}), 200
    return jsonify({'message': 'User not found'}), 404


@app.route('/users', methods=['GET'])
def list_users():
    """Return list of registered users (pseudonym + username) for the UI."""
    try:
        user_id = decode_token(request.headers.get('Authorization'))
    except ValueError as e:
        return jsonify({'message': str(e)}), 401

    users = User.query.all()
    return jsonify([{'username': u.username, 'pseudonym': u.pseudonym,
                     'online': u.pseudonym in DHT} for u in users]), 200


# ── API: Messaging ────────────────────────────────────────────────────────────
@app.route('/store_offline_message', methods=['POST'])
def store_offline_message():
    try:
        user_id = decode_token(request.headers.get('Authorization'))
    except ValueError as e:
        return jsonify({'message': str(e)}), 401

    sender = db.session.get(User, user_id)   # FIX: deprecated .get()
    if not sender:
        return jsonify({'message': 'User not found'}), 404

    body = request.get_json() or {}
    recipient_pseudonym = body.get('recipient_pseudonym')
    encrypted_message   = body.get('encrypted_message')

    if not recipient_pseudonym or not encrypted_message:
        return jsonify({'message': 'Missing required fields'}), 400

    msg = OfflineMessage(
        recipient_pseudonym=recipient_pseudonym,
        sender_pseudonym=sender.pseudonym,
        encrypted_message=encrypted_message
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({'message': 'Message stored'}), 200


@app.route('/get_offline_messages/<pseudonym>', methods=['GET'])
def get_offline_messages(pseudonym):
    try:
        user_id = decode_token(request.headers.get('Authorization'))
    except ValueError as e:
        return jsonify({'message': str(e)}), 401

    user = db.session.get(User, user_id)   # FIX: deprecated .get()
    if not user or user.pseudonym != pseudonym:
        return jsonify({'message': 'Unauthorized'}), 403

    messages = OfflineMessage.query.filter_by(recipient_pseudonym=pseudonym).all()
    result = [{'id': m.id, 'sender_pseudonym': m.sender_pseudonym,
               'encrypted_message': m.encrypted_message,
               'timestamp': m.timestamp.isoformat()} for m in messages]

    for m in messages:
        db.session.delete(m)
    db.session.commit()

    return jsonify({'messages': result}), 200


# ── API: DH parameters (so browser client can exchange keys) ──────────────────
@app.route('/dh_parameters', methods=['GET'])
def get_dh_parameters():
    """Return serialized DH parameters so clients can generate matching keys."""
    from cryptography.hazmat.primitives import serialization
    pem = DH_PARAMETERS.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ).decode('utf-8')
    return jsonify({'dh_parameters': pem}), 200


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("Starting Secure Messenger server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
