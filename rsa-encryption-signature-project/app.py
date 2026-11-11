from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import os
from datetime import datetime
import bcrypt
import traceback

# Compatibility fix for Werkzeug
try:
    from werkzeug.urls import url_decode
except ImportError:
    from urllib.parse import unquote
    def url_decode(url, charset='utf-8', decode_keys=False):
        return unquote(url)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    key_size = db.Column(db.Integer, default=2048)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_message = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    message_hash = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_rsa_keys(key_size):
    """Generate RSA public and private keys"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
    except Exception as e:
        print(f"Key generation error: {e}")
        print(traceback.format_exc())
        return None, None

def encrypt_message(message, public_key_pem):
    """Encrypt message using public key"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        encrypted = public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        print(traceback.format_exc())
        return None

def decrypt_message(encrypted_message, private_key_pem):
    """Decrypt message using private key"""
    try:
        # Check if private key exists
        if not private_key_pem:
            print("No private key provided")
            return None
            
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))
        
        # Decrypt
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        print(traceback.format_exc())
        return None

def generate_signature(message, private_key_pem):
    """Generate digital signature for message"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        print(f"Signature error: {e}")
        return None

def verify_signature(message, signature, public_key_pem):
    """Verify digital signature"""
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        
        public_key.verify(
            signature_bytes,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
    except Exception as e:
        print(f"Verification error: {e}")
        return False

def compute_hash(message):
    """Compute SHA-256 hash of message"""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode('utf-8'))
    hash_bytes = digest.finalize()
    return base64.b64encode(hash_bytes).decode('utf-8')[:16]

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', user=current_user)
    return render_template('index.html', user=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.json
        user = User.query.filter_by(username=data.get('username')).first()
        
        if user and user.check_password(data.get('password')):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return jsonify({'success': True, 'username': user.username})
        
        return jsonify({'success': False, 'error': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already exists'})
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'})
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        # Generate default keys
        private_key, public_key = generate_rsa_keys(2048)
        if private_key and public_key:
            user.private_key = private_key
            user.public_key = public_key
            user.key_size = 2048
        
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        return jsonify({'success': True, 'username': username})
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/generate_keys')
@login_required
def generate_keys_page():
    return render_template('generate_keys.html', user=current_user)

@app.route('/encrypt_sign')
@login_required
def encrypt_sign_page():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('encrypt_sign.html', user=current_user, users=users)

@app.route('/decrypt_verify')
@login_required
def decrypt_verify_page():
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    return render_template('decrypt_verify.html', user=current_user, messages=messages)

@app.route('/workflow')
def workflow_page():
    return render_template('workflow.html', user=current_user if current_user.is_authenticated else None)

# API Routes
@app.route('/api/generate_keys', methods=['POST'])
@login_required
def api_generate_keys():
    data = request.json
    key_size = int(data.get('key_size', 2048))
    
    private_key, public_key = generate_rsa_keys(key_size)
    
    if private_key and public_key:
        session['temp_private_key'] = private_key
        session['temp_public_key'] = public_key
        
        return jsonify({
            'success': True,
            'private_key': private_key,
            'public_key': public_key,
            'key_size': key_size
        })
    else:
        return jsonify({'success': False, 'error': 'Failed to generate keys'})

@app.route('/api/save_keys', methods=['POST'])
@login_required
def api_save_keys():
    if 'temp_private_key' in session and 'temp_public_key' in session:
        current_user.private_key = session['temp_private_key']
        current_user.public_key = session['temp_public_key']
        db.session.commit()
        return jsonify({'success': True, 'message': 'Keys saved permanently'})
    return jsonify({'success': False, 'error': 'No temporary keys found'})

@app.route('/api/clear_keys', methods=['POST'])
@login_required
def api_clear_keys():
    session.pop('temp_private_key', None)
    session.pop('temp_public_key', None)
    
    if request.json.get('clear_database', False):
        current_user.private_key = None
        current_user.public_key = None
        db.session.commit()
    
    return jsonify({'success': True, 'message': 'Keys cleared successfully'})

@app.route('/api/get_user_public_key/<username>', methods=['GET'])
@login_required
def api_get_user_public_key(username):
    user = User.query.filter_by(username=username).first()
    if user and user.public_key:
        return jsonify({'success': True, 'public_key': user.public_key, 'username': user.username})
    return jsonify({'success': False, 'error': 'User not found or no public key'})

@app.route('/api/encrypt_sign', methods=['POST'])
@login_required
def api_encrypt_sign():
    data = request.json
    message = data.get('message', '')
    receiver_username = data.get('receiver_username', '')
    sender_private_key = data.get('sender_private_key', current_user.private_key)
    
    if not sender_private_key:
        return jsonify({'success': False, 'error': 'You don\'t have a private key. Generate keys first!'})
    
    receiver = User.query.filter_by(username=receiver_username).first()
    if not receiver or not receiver.public_key:
        return jsonify({'success': False, 'error': 'Receiver not found or has no public key'})
    
    encrypted_message = encrypt_message(message, receiver.public_key)
    if encrypted_message is None:
        return jsonify({'success': False, 'error': 'Encryption failed. Check if receiver has valid keys.'})
    
    signature = generate_signature(message, sender_private_key)
    if signature is None:
        return jsonify({'success': False, 'error': 'Signature generation failed'})
    
    message_hash = compute_hash(message)
    
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        encrypted_message=encrypted_message,
        signature=signature,
        message_hash=message_hash
    )
    db.session.add(new_message)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'encrypted_message': encrypted_message,
        'signature': signature,
        'message_hash': message_hash,
        'receiver': receiver_username,
        'sender': current_user.username,
        'message_id': new_message.id
    })

# Add this updated API endpoint for marking messages as read
@app.route('/api/mark_message_read', methods=['POST'])
@login_required
def api_mark_message_read():
    data = request.json
    message_id = data.get('message_id')
    
    if message_id:
        message = Message.query.get(message_id)
        if message and message.receiver_id == current_user.id:
            message.is_read = True
            db.session.commit()
            return jsonify({'success': True, 'message': 'Message marked as read'})
    
    return jsonify({'success': False, 'error': 'Message not found'})

# Update the existing api_decrypt_verify endpoint
@app.route('/api/decrypt_verify', methods=['POST'])
@login_required
def api_decrypt_verify():
    try:
        data = request.json
        encrypted_message = data.get('encrypted_message', '')
        signature = data.get('signature', '')
        sender_username = data.get('sender_username', '')
        message_id = data.get('message_id')  # Add this to receive message_id
        
        # Check if user has private key
        if not current_user.private_key:
            return jsonify({'success': False, 'error': 'You don\'t have a private key. Please generate keys first!'})
        
        # Get sender's public key
        sender = User.query.filter_by(username=sender_username).first()
        if not sender:
            return jsonify({'success': False, 'error': f'Sender "{sender_username}" not found'})
        
        if not sender.public_key:
            return jsonify({'success': False, 'error': f'Sender "{sender_username}" has no public key'})
        
        # Decrypt message
        decrypted_message = decrypt_message(encrypted_message, current_user.private_key)
        if decrypted_message is None:
            return jsonify({'success': False, 'error': 'Decryption failed. Make sure:\n1. You have the correct private key\n2. The message was encrypted with YOUR public key\n3. The encrypted message is not corrupted'})
        
        # Verify signature
        is_valid = verify_signature(decrypted_message, signature, sender.public_key)
        
        # Mark message as read if message_id provided
        if message_id and is_valid:
            msg = Message.query.get(message_id)
            if msg and msg.receiver_id == current_user.id:
                msg.is_read = True
                db.session.commit()
        
        return jsonify({
            'success': True,
            'decrypted_message': decrypted_message,
            'signature_valid': is_valid,
            'sender_username': sender.username,
            'sender_identity_verified': is_valid
        })
    except Exception as e:
        print(f"Decrypt verify error: {e}")
        print(traceback.format_exc())
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/api/my_messages', methods=['GET'])
@login_required
def api_my_messages():
    messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).limit(50).all()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender': msg.sender.username if msg.sender else 'Unknown',
            'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_read': msg.is_read,
            'encrypted_message_preview': msg.encrypted_message[:50] + '...'
        })
    
    return jsonify({'success': True, 'messages': messages_data})

@app.route('/api/check_keys', methods=['GET'])
@login_required
def api_check_keys():
    """Debug endpoint to check key status"""
    return jsonify({
        'has_private_key': bool(current_user.private_key),
        'has_public_key': bool(current_user.public_key),
        'key_size': current_user.key_size,
        'private_key_preview': current_user.private_key[:100] if current_user.private_key else None,
        'public_key_preview': current_user.public_key[:100] if current_user.public_key else None
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)