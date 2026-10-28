"""Educational multi-application payment architecture demo; no real payments."""
import argparse
import logging
import os
import re
import secrets
import sqlite3
import hmac
from decimal import Decimal, InvalidOperation
from pathlib import Path
from getpass import getpass
from contextlib import contextmanager

from flask import Flask, abort, flash, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "instance" / "payments.sqlite3"
app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get("APP_SECRET") or secrets.token_hex(32),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
                  MAX_CONTENT_LENGTH=16_384)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("payment-demo")


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def idempotency_key():
    if "idem" not in session:
        session["idem"] = secrets.token_urlsafe(24)
    return session["idem"]


app.jinja_env.globals.update(csrf_token=csrf_token, idempotency_key=idempotency_key)


@app.before_request
def protect_posts():
    if request.method == "POST":
        expected = session.get("csrf", "")
        supplied = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, supplied):
            abort(400, "Invalid request token.")

PAGE = """<!doctype html><meta charset="utf-8"><title>Northstar Pay Demo</title>
<h1>Northstar Pay - local security prototype</h1><p>Simulated payments only. Never enter real card data.</p>
{% for msg in get_flashed_messages() %}<p role="status">{{ msg }}</p>{% endfor %}
{% if session.get('uid') %}<p>Signed in as {{ session.email }} ({{ session.role }})</p>
<p><a href="/customer">Customer portal</a> · <a href="/admin">Admin portal</a> · <a href="/api/v1/me">API status</a></p>
<form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button>Sign out</button></form>
{% else %}<h2>Register customer</h2><form method="post" action="/customer/register"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" minlength="12" required></label><button>Register</button></form>
<h2>Sign in</h2><form method="post" action="/customer/login"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" required></label><button>Sign in</button></form>
<h2>Administrator sign in</h2><form method="post" action="/admin/login"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><label>Email <input name="email" type="email" required></label><label>Password <input name="password" type="password" required></label><button>Sign in to admin</button></form>{% endif %}"""
CUSTOMER = """<!doctype html><title>Customer Portal</title><h1>Customer portal</h1><p>Payments are simulated; no funds move.</p>
<h2>Simulate payment</h2><form method="post" action="/payment/charge"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="idempotency_key" value="{{ idempotency_key() }}"><label>Amount (1.00-500.00 credits) <input name="amount" type="number" min="1" max="500" step="0.01" required></label><button>Simulate</button></form>
<h2>Recent payments</h2><ul>{% for p in payments %}<li>{{ p[0] }} credits · {{ p[1] }}</li>{% else %}<li>No payments yet.</li>{% endfor %}</ul><a href="/">Home</a>"""
ADMIN = """<!doctype html><title>Admin Portal</title><h1>Admin portal</h1><p>Simulated ledger entries</p><ul>{% for r in rows %}<li>{{ r[0] }} · {{ r[1] }} · {{ r[2] }} · {{ r[3] }}</li>{% endfor %}</ul><a href="/">Home</a>"""


@contextmanager
def connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('customer','admin')));
      CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),amount_cents INTEGER NOT NULL CHECK(amount_cents BETWEEN 100 AND 50000),status TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY,payment_id TEXT NOT NULL REFERENCES payments(id),account TEXT NOT NULL,side TEXT NOT NULL CHECK(side IN ('debit','credit')),amount_cents INTEGER NOT NULL CHECK(amount_cents>0));
    """)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


@app.after_request
def harden(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; form-action 'self'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response


def require_user(role=None):
    uid = session.get("uid")
    if not uid:
        abort(401)
    if role and session.get("role") != role:
        abort(403)
    return uid


@app.get("/")
def home():
    return render_template_string(PAGE)


@app.post("/customer/register")
def register():
    email, password = request.form.get("email", "").strip().lower(), request.form.get("password", "")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not 12 <= len(password) <= 256:
        abort(400, "Use a valid email and a password between 12 and 256 characters.")
    try:
        with connect() as conn:
            conn.execute("INSERT INTO users(email,password_hash,role) VALUES (?,?, 'customer')", (email, generate_password_hash(password)))
    except sqlite3.IntegrityError:
        flash("Account could not be created with those details.")
        return redirect(url_for("home"))
    return login_account(email, password)


def login_account(email, password):
    with connect() as conn:
        row = conn.execute("SELECT id,password_hash,role FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password_hash(row[1], password):
        log.warning("authentication_failed")
        flash("Email or password is incorrect.")
        return redirect(url_for("home"))
    session.clear()
    session.update(uid=row[0], email=email, role=row[2])
    log.info("authentication_success role=%s", row[2])
    return redirect(url_for("home"))


@app.post("/customer/login")
def customer_login():
    return login_account(request.form.get("email", "").strip().lower(), request.form.get("password", ""))


@app.post("/admin/login")
def admin_login():
    return login_account(request.form.get("email", "").strip().lower(), request.form.get("password", ""))


@app.get("/customer")
def customer_portal():
    uid = require_user("customer")
    with connect() as conn:
        payments = conn.execute("SELECT amount_cents / 100.0, status FROM payments WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (uid,)).fetchall()
    return render_template_string(CUSTOMER, payments=payments)


@app.post("/payment/charge")
def charge():
    uid = require_user("customer")
    try:
        amount = Decimal(request.form.get("amount", ""))
        cents = int(amount * 100)
    except (InvalidOperation, ValueError):
        abort(400, "Invalid amount.")
    if amount != Decimal(cents) / 100 or not 100 <= cents <= 50000:
        abort(400, "Amount must be from 1.00 to 500.00 credits, with two decimal places.")
    idem = request.headers.get("Idempotency-Key") or request.form.get("idempotency_key", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", idem):
        abort(400, "Invalid idempotency key.")
    payment_id = idem
    try:
        with connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO payments(id,user_id,amount_cents,status) VALUES (?,?,?,'approved')", (payment_id, uid, cents))
            conn.execute("INSERT INTO ledger(payment_id,account,side,amount_cents) VALUES (?,?,?,?),(?,?,?,?)",
                         (payment_id, "customer-clearing", "debit", cents, payment_id, "merchant-clearing", "credit", cents))
    except sqlite3.IntegrityError:
        flash("This payment request was already processed or could not be completed.")
        return redirect(url_for("customer_portal"))
    log.info("payment_simulated user_id=%s payment_id=%s amount_cents=%s", uid, payment_id, cents)
    session.pop("idem", None)
    flash("Simulated payment recorded. No funds moved.")
    return redirect(url_for("customer_portal"))


@app.get("/admin")
def admin_portal():
    require_user("admin")
    with connect() as conn:
        rows = conn.execute("SELECT p.id,p.status,l.account,l.amount_cents FROM payments p JOIN ledger l ON l.payment_id=p.id ORDER BY p.created_at DESC LIMIT 100").fetchall()
    return render_template_string(ADMIN, rows=rows)


@app.get("/api/v1/me")
def api_me():
    uid = require_user()
    return jsonify({"account_id": uid, "role": session["role"], "service": "payment-demo", "mode": "simulation"})


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


def create_admin(email):
    password = getpass("Administrator password (12+ characters): ")
    if len(password) < 12 or len(password) > 256 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SystemExit("Use a valid email and a 12–256 character password.")
    with connect() as conn:
        conn.execute("INSERT INTO users(email,password_hash,role) VALUES (?,?, 'admin')", (email.lower(), generate_password_hash(password)))
    print("Administrator created.")


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--create-admin", metavar="EMAIL")
    opts = cli.parse_args()
    if opts.create_admin:
        create_admin(opts.create_admin.strip())
    else:
        app.run(host="127.0.0.1", port=5100, debug=False)

