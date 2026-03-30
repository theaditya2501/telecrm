import firebase_admin
from firebase_admin import credentials, firestore
import hashlib
import datetime

# ── Firebase Init ──────────────────────────────────────────
cred = credentials.Certificate("firebase.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# ── Config ─────────────────────────────────────────────────
PROJECT_ID = "telecallercrm-45ec7"
USERS_PATH = f"artifacts/{PROJECT_ID}/public/data/users"

USERNAME = "admin"
PASSWORD = "Upscale@1997"
ROLE     = "admin"

# ── Hash password (same way main.py does it) ───────────────
hashed = hashlib.sha256(PASSWORD.encode()).hexdigest()

# ── Check if user already exists ──────────────────────────
existing = db.collection(USERS_PATH)\
             .where("username", "==", USERNAME)\
             .limit(1).get()

if existing:
    print(f"⚠️  User '{USERNAME}' already exists. Aborting.")
else:
    db.collection(USERS_PATH).add({
        "username":   USERNAME,
        "password":   hashed,
        "role":       ROLE,
        "created_at": datetime.datetime.utcnow()
    })
    print(f"✅ Admin user '{USERNAME}' created successfully!")
    print(f"   Role     : {ROLE}")
    print(f"   Project  : {PROJECT_ID}")
    print(f"   Login at : your-server/  →  use '{USERNAME}' + your password")