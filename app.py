```
import os
from decimal import Decimal, InvalidOperation
from functools import wraps

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
DATABASE_URL = os.environ.get("DATABASE_URL")


def db():
    """Connect to PostgreSQL using DATABASE_URL."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured.")

    database_url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)


def init_db():
    """Create tables and seed the admin account once."""
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    pin_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'customer')),
                    balance NUMERIC(12, 2) NOT NULL DEFAULT 0
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    transaction_type TEXT NOT NULL,
                    amount NUMERIC(12, 2) NOT NULL,
                    balance_after NUMERIC(12, 2) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur.execute("SELECT id FROM users WHERE username = %s", ("admin",))
            if cur.fetchone() is None:
                admin_pin = os.environ.get("ADMIN_INITIAL_PIN")
                if not admin_pin:
                    raise RuntimeError(
                        "Set ADMIN_INITIAL_PIN before the first application startup."
                    )
                cur.execute("""
                    INSERT INTO users
                        (username, full_name, pin_hash, role, balance)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    "admin",
                    "System Administrator",
                    generate_password_hash(admin_pin),
                    "admin",
                    Decimal("0.00"),
                ))


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
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cur.fetchone()

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
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
            user = cur.fetchone()

            if user is None:
                session.clear()
                return redirect(url_for("login"))

            if user["role"] == "admin":
                cur.execute("""
                    SELECT id, username, full_name, balance
                    FROM users
                    WHERE role = 'customer'
                    ORDER BY id DESC
                """)
                customers = cur.fetchall()
                return render_template("admin.html", user=user, customers=customers)

            cur.execute("""
                SELECT * FROM transactions
                WHERE user_id = %s
                ORDER BY id DESC
                LIMIT 10
            """, (user["id"],))
            transactions = cur.fetchall()

    return render_template("customer.html", user=user, transactions=transactions)


@app.route("/admin/create-customer", methods=["POST"])
@login_required("admin")
def create_customer():
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    default_pin = request.form.get("default_pin", "").strip()

    if not username or not full_name or not default_pin.isdigit() or len(default_pin) < 4:
        flash(
            "Enter a name, username, and a numeric default PIN of at least 4 digits.",
            "error",
        )
        return redirect(url_for("dashboard"))

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users
                        (username, full_name, pin_hash, role, balance)
                    VALUES (%s, %s, %s, 'customer', 0)
                """, (username, full_name, generate_password_hash(default_pin)))

        flash(
            "Customer account created. Give the customer their username and default PIN securely.",
            "success",
        )
    except psycopg2.IntegrityError:
        flash("That username already exists. Choose another username.", "error")

    return redirect(url_for("dashboard"))


@app.route("/transaction/<action>", methods=["POST"])
@login_required("customer")
def transaction(action):
    if action not in ("deposit", "withdraw"):
        return redirect(url_for("dashboard"))

    try:
        amount = Decimal(request.form.get("amount", "0")).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError):
        amount = Decimal("0.00")

    confirm_pin = request.form.get("confirm_pin", "")

    if not amount.is_finite() or amount <= 0:
        flash("Enter an amount greater than zero.", "error")
        return redirect(url_for("dashboard"))

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE id = %s FOR UPDATE",
                (session["user_id"],),
            )
            user = cur.fetchone()

            if user is None:
                session.clear()
                return redirect(url_for("login"))

            if not check_password_hash(user["pin_hash"], confirm_pin):
                flash("PIN verification failed. Transaction cancelled.", "error")
                return redirect(url_for("dashboard"))

            if action == "withdraw" and amount > user["balance"]:
                flash("Insufficient funds. Transaction cancelled.", "error")
                return redirect(url_for("dashboard"))

            new_balance = (
                user["balance"] + amount
                if action == "deposit"
                else user["balance"] - amount
            )

            cur.execute(
                "UPDATE users SET balance = %s WHERE id = %s",
                (new_balance, user["id"]),
            )
            cur.execute("""
                INSERT INTO transactions
                    (user_id, transaction_type, amount, balance_after)
                VALUES (%s, %s, %s, %s)
            """, (user["id"], action.capitalize(), amount, new_balance))

    flash(
        f"{action.capitalize()} successful. New balance: ₱{new_balance:,.2f}",
        "success",
    )
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
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE id = %s FOR UPDATE",
                (session["user_id"],),
            )
            user = cur.fetchone()

            if user is None:
                session.clear()
                return redirect(url_for("login"))

            if not check_password_hash(user["pin_hash"], current_pin):
                flash("Current PIN is incorrect.", "error")
                return redirect(url_for("dashboard"))

            cur.execute(
                "UPDATE users SET pin_hash = %s WHERE id = %s",
                (generate_password_hash(new_pin), user["id"]),
            )

    flash("PIN changed successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/history")
@login_required("customer")
def history():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM transactions
                WHERE user_id = %s
                ORDER BY id DESC
            """, (session["user_id"],))
            transactions = cur.fetchall()

    return render_template("history.html", transactions=transactions)


# Initialize PostgreSQL tables when the application starts under Flask or Gunicorn.
with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=False)

```
