
import json
from flask import send_file

from flask import Flask, render_template, request, redirect, session
import sqlite3
from flask_bcrypt import Bcrypt
from encryption import encrypt_password, decrypt_password
import secrets
import string

app = Flask(__name__)
app.secret_key = "supersecretkey"

bcrypt = Bcrypt(app)


def get_db():
    return sqlite3.connect("database.db")


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        site TEXT,
        site_username TEXT,
        site_password TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()

# Register
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed = bcrypt.generate_password_hash(password).decode()

        conn = get_db()
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO users(username,password) VALUES(?,?)",
                        (username,hashed))
            conn.commit()
        except:
            return "User already exists"

        return redirect("/login")

    return render_template("register.html")


# Login
@app.route("/", methods=["GET","POST"])
@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["master"] = password

            return redirect("/dashboard")

        return "Invalid login"

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM vault WHERE user_id=?", (session["user_id"],))
    data = cur.fetchall()

    passwords = []

    for row in data:
        try:
            decrypted = decrypt_password(row[4], session["master"])
        except:
            decrypted = "ERROR"

        passwords.append({
            "id":row[0],
            "site":row[2],
            "username":row[3],
            "password":decrypted
        })

    return render_template("dashboard.html", passwords=passwords)


# Add credential
@app.route("/add", methods=["POST"])
def add():

    site = request.form["site"]
    username = request.form["username"]
    password = request.form["password"]

    encrypted = encrypt_password(password, session["master"])

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO vault(user_id,site,site_username,site_password) VALUES(?,?,?,?)",
        (session["user_id"],site,username,encrypted)
    )

    conn.commit()

    return redirect("/dashboard")


# Delete
@app.route("/delete/<int:id>")
def delete(id):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM vault WHERE id=?", (id,))
    conn.commit()

    return redirect("/dashboard")


# Password Generator
@app.route("/generate")
def generate():

    chars = string.ascii_letters + string.digits + "!@#$%"

    password = "".join(secrets.choice(chars) for _ in range(12))

    return password


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/export")
def export_vault():

    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT site, site_username, site_password FROM vault WHERE user_id=?", (session["user_id"],))

    data = cur.fetchall()

    vault = []

    for row in data:
        vault.append({
            "site": row[0],
            "username": row[1],
            "password": row[2]  # encrypted password
        })

    with open("vault_backup.json", "w") as f:
        json.dump(vault, f, indent=4)

    return send_file("vault_backup.json", as_attachment=True)


@app.route("/import", methods=["POST"])
def import_vault():

    if "user_id" not in session:
        return redirect("/login")

    file = request.files["file"]

    data = json.load(file)

    conn = get_db()
    cur = conn.cursor()

    for entry in data:

        cur.execute(
        "INSERT INTO vault(user_id,site,site_username,site_password) VALUES(?,?,?,?)",
        (session["user_id"], entry["site"], entry["username"], entry["password"])
        )

    conn.commit()

    return redirect("/dashboard")
if __name__ == "__main__":
    app.run(debug=True)