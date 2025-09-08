from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, secrets, json

app = Flask(__name__)
CORS(app)
DB = "db.sqlite3"

def con():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    c = con(); cur = c.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS tokens(id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT UNIQUE)")
    cur.execute("CREATE TABLE IF NOT EXISTS residents(id INTEGER PRIMARY KEY, name TEXT, age INTEGER, room TEXT, notes TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS medications(id INTEGER PRIMARY KEY, resident_id INTEGER, drug TEXT, dose TEXT, route TEXT, frequency TEXT, times TEXT, start_date TEXT, end_date TEXT, notes TEXT, active INTEGER DEFAULT 1)")
    cur.execute("CREATE TABLE IF NOT EXISTS finance_receipts(id INTEGER PRIMARY KEY, date TEXT, description TEXT, amount REAL, resident_id INTEGER, category TEXT, notes TEXT)")
    cur.execute("CREATE TABLE IF NOT EXISTS finance_expenses(id INTEGER PRIMARY KEY, date TEXT, description TEXT, amount REAL, resident_id INTEGER, category TEXT, notes TEXT)")
    c.commit(); c.close()

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

def auth_user():
    token = request.headers.get('Authorization','').replace('Bearer ','').strip()
    if not token: return None
    c = con(); cur = c.cursor()
    cur.execute("SELECT users.id, users.email FROM tokens JOIN users ON users.id=tokens.user_id WHERE tokens.token=?", (token,))
    row = cur.fetchone(); c.close()
    return None if not row else {"id":row[0], "email":row[1]}

@app.post("/auth/signup")
def signup():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password: return ("email/senha obrigatórios", 400)
    try:
        c=con(); cur=c.cursor()
        cur.execute("INSERT INTO users(email,password_hash) VALUES(?,?)", (email, hash_pw(password)))
        c.commit(); c.close()
        return jsonify({"ok": True}), 201
    except sqlite3.IntegrityError:
        return ("email já cadastrado", 400)

@app.post("/auth/login")
def login():
    data = request.get_json() or {}
    email, password = data.get("email"), data.get("password")
    c=con(); cur=c.cursor()
    cur.execute("SELECT id,password_hash FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row or row[1] != hash_pw(password): c.close(); return ("credenciais inválidas", 401)
    user_id = row[0]; token = secrets.token_hex(16)
    cur.execute("INSERT INTO tokens(user_id, token) VALUES(?,?)", (user_id, token))
    c.commit(); c.close()
    return jsonify({"token": token, "user": {"id": user_id, "email": email}})

@app.get("/residents")
def list_residents():
    if not auth_user(): return ("unauthorized", 401)
    c=con(); cur=c.cursor()
    cur.execute("SELECT id,name,age,room,notes FROM residents ORDER BY id DESC")
    rows = cur.fetchall(); c.close()
    return jsonify([{"id":r[0],"name":r[1],"age":r[2],"room":r[3],"notes":r[4]} for r in rows])

@app.post("/residents")
def create_resident():
    if not auth_user(): return ("unauthorized", 401)
    d = request.get_json() or {}
    c=con(); cur=c.cursor()
    cur.execute("INSERT INTO residents(name,age,room,notes) VALUES(?,?,?,?)",
                (d.get("name"), d.get("age"), d.get("room"), d.get("notes")))
    c.commit(); rid = cur.lastrowid; c.close()
    return jsonify({"id":rid,**d}), 201

@app.put("/residents/<int:rid>")
def update_resident(rid):
    if not auth_user(): return ("unauthorized", 401)
    d=request.get_json() or {}
    c=con(); cur=c.cursor()
    cur.execute("UPDATE residents SET name=?, age=?, room=?, notes=? WHERE id=?",
                (d.get("name"), d.get("age"), d.get("room"), d.get("notes"), rid))
    c.commit(); c.close()
    return jsonify({"ok": True})

@app.delete("/residents/<int:rid>")
def delete_resident(rid):
    if not auth_user(): return ("unauthorized", 401)
    c=con(); cur=c.cursor(); cur.execute("DELETE FROM residents WHERE id=?", (rid,))
    c.commit(); c.close()
    return "", 204

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
