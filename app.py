import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-for-deployment")
DB_PATH = os.path.join(os.path.dirname(__file__), "banking.db")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                pin_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','customer')),
                balance REAL NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL,
                balance_after REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        admin = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not admin:
            conn.execute(
                "INSERT INTO users (username, full_name, pin_hash, role, balance) VALUES (?, ?, ?, ?, ?)",
                ("admin", "System Administrator", generate_password_hash("1234"), "admin", 0)
            )

def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You are not authorized to access that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pin = request.form.get("pin", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["pin_hash"], pin):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or PIN.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required()
def dashboard():
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if user["role"] == "admin":
            customers = conn.execute(
                "SELECT id, username, full_name, balance FROM users WHERE role = 'customer' ORDER BY id DESC"
            ).fetchall()
            return render_template("admin.html", user=user, customers=customers)
        transactions = conn.execute(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 10",
            (user["id"],)
        ).fetchall()
    return render_template("customer.html", user=user, transactions=transactions)

@app.route("/admin/create-customer", methods=["POST"])
@login_required("admin")
def create_customer():
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    default_pin = request.form.get("default_pin", "").strip()
    if not username or not full_name or not default_pin.isdigit() or len(default_pin) < 4:
        flash("Enter a name, username, and a numeric default PIN of at least 4 digits.", "error")
        return redirect(url_for("dashboard"))
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users (username, full_name, pin_hash, role, balance) VALUES (?, ?, ?, 'customer', 0)",
                (username, full_name, generate_password_hash(default_pin))
            )
        flash(f"Customer account created. Give the customer their username and default PIN securely.", "success")
    except sqlite3.IntegrityError:
        flash("That username already exists. Choose another username.", "error")
    return redirect(url_for("dashboard"))

@app.route("/transaction/<action>", methods=["POST"])
@login_required("customer")
def transaction(action):
    if action not in ("deposit", "withdraw"):
        return redirect(url_for("dashboard"))
    try:
        amount = round(float(request.form.get("amount", "0")), 2)
    except ValueError:
        amount = 0
    confirm_pin = request.form.get("confirm_pin", "")
    if amount <= 0:
        flash("Enter an amount greater than zero.", "error")
        return redirect(url_for("dashboard"))

    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not check_password_hash(user["pin_hash"], confirm_pin):
            flash("PIN verification failed. Transaction cancelled.", "error")
            return redirect(url_for("dashboard"))
        if action == "withdraw" and amount > user["balance"]:
            flash("Insufficient funds. Transaction cancelled.", "error")
            return redirect(url_for("dashboard"))
        new_balance = user["balance"] + amount if action == "deposit" else user["balance"] - amount
        conn.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, user["id"]))
        conn.execute(
            "INSERT INTO transactions (user_id, transaction_type, amount, balance_after) VALUES (?, ?, ?, ?)",
            (user["id"], action.capitalize(), amount, new_balance)
        )
    flash(f"{action.capitalize()} successful. New balance: ₱{new_balance:,.2f}", "success")
    return redirect(url_for("dashboard"))

@app.route("/change-pin", methods=["POST"])
@login_required("customer")
def change_pin():
    current_pin = request.form.get("current_pin", "")
    new_pin = request.form.get("new_pin", "").strip()
    if not new_pin.isdigit() or len(new_pin) < 4:
        flash("Your new PIN must contain at least 4 digits.", "error")
        return redirect(url_for("dashboard"))
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not check_password_hash(user["pin_hash"], current_pin):
            flash("Current PIN is incorrect.", "error")
            return redirect(url_for("dashboard"))
        conn.execute("UPDATE users SET pin_hash = ? WHERE id = ?",
                     (generate_password_hash(new_pin), user["id"]))
    flash("PIN changed successfully.", "success")
    return redirect(url_for("dashboard"))

@app.route("/history")
@login_required("customer")
def history():
    with db() as conn:
        transactions = conn.execute(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],)
        ).fetchall()
    return render_template("history.html", transactions=transactions)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
