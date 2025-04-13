from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import numpy as np
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Setup SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)

# Face detection setup
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

# Create the database
with app.app_context():
    db.create_all()

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Detect faces
def detect_faces(image_array):
    gray = cv2.cvtColor(image_array, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)
    return faces

#Signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    new_user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": f"User {username} registered successfully!"})

#Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if user and user.verify_password(password):
        login_user(user)
        return jsonify({"message": f"Logged in as {username}!"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

# Route: Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out!"})

#Face Detection (image file upload)
@app.route('/detect_face', methods=['POST'])
@login_required
def detect_face():
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400

    file = request.files['image']
    img_np = np.frombuffer(file.read(), np.uint8)
    img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)

    faces = detect_faces(img)
    return jsonify({
        "faces_detected": len(faces),
        "user": current_user.username
    })

#Extremist Language Detection
@app.route('/detect_text', methods=['POST'])
@login_required
def detect_text():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "Text not provided"}), 400

    text = data['text'].lower()
    extremist_keywords = ["bomb", "attack", "kill", "jihad", "terror"]
    found = [word for word in extremist_keywords if word in text]

    if found:
        return jsonify({"status": "warning", "keywords": found})
    else:
        return jsonify({"status": "safe"})

if __name__ == '__main__':
    app.run(debug=True)
