from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import io
import os
import secrets
import sqlite3
import time

import pandas as pd
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("ERP_SECRET_KEY", "change-this-secret-in-production")
CORS(
    app,
    resources={r"/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000", "http://localhost:8000", "http://localhost", "http://127.0.0.1", "null"], "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}},
)

SESSION_TIMEOUT_SECONDS = 3600
SESSIONS = {}


def get_db_connection():
    conn = sqlite3.connect("enterprise_erp.db")
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(stored_password, supplied_password):
    if not stored_password or not supplied_password:
        return False
    try:
        if check_password_hash(stored_password, supplied_password):
            return True
    except ValueError:
        pass
    return stored_password == supplied_password


def prune_sessions():
    now = time.time()
    for token in list(SESSIONS.keys()):
        if now - SESSIONS[token]["created_at"] > SESSION_TIMEOUT_SECONDS:
            del SESSIONS[token]


def get_authenticated_user():
    prune_sessions()
    auth_header = request.headers.get("Authorization", "")
    token = None

    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif request.args.get("token"):
        token = request.args.get("token")
    elif request.form.get("token"):
        token = request.form.get("token")

    if not token:
        return None, (jsonify({"success": False, "message": "Authentication required."}), 401)

    user = SESSIONS.get(token)
    if not user:
        return None, (jsonify({"success": False, "message": "Session expired or invalid."}), 401)

    return user, None


def require_admin():
    user, error = get_authenticated_user()
    if error:
        return None, error
    if user["role"] != "Admin":
        return None, (jsonify({"success": False, "message": "Permission Denied! Only Admins can perform this action."}), 403)
    return user, None


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_name TEXT NOT NULL,
            contact_details TEXT,
            supply_category TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emp_name TEXT NOT NULL,
            emp_role TEXT,
            emp_phone TEXT
        )
        """
    )

    default_users = [("admin", "123", "Admin"), ("staff", "123", "Staff")]
    for username, raw_password, role in default_users:
        existing = cursor.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
        if existing is None:
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hash_password(raw_password), role),
            )
        elif not existing["password"].startswith("pbkdf2"):
            cursor.execute(
                "UPDATE users SET password = ?, role = ? WHERE username = ?",
                (hash_password(raw_password), role, username),
            )

    conn.commit()
    conn.close()


init_db()


@app.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"success": False, "message": "JSON payload required."}), 400

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400

    conn = get_db_connection()
    user_row = conn.execute(
        "SELECT id, username, password, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if not user_row:
        return jsonify({"success": False, "message": "Invalid username or password!"}), 401

    if not verify_password(user_row["password"], password):
        return jsonify({"success": False, "message": "Invalid username or password!"}), 401

    if not user_row["password"].startswith("pbkdf2"):
        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hash_password(password), user_row["id"]),
        )
        conn.commit()
        conn.close()

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "user_id": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "created_at": time.time(),
    }

    return jsonify({
        "success": True,
        "username": user_row["username"],
        "role": user_row["role"],
        "token": token,
        "message": "Login successful!"
    })


@app.route("/logout", methods=["POST"])
def logout():
    user, error = get_authenticated_user()
    if error:
        return error

    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif request.args.get("token"):
        token = request.args.get("token")
    elif request.form.get("token"):
        token = request.form.get("token")

    if token:
        SESSIONS.pop(token, None)

    return jsonify({"success": True, "message": "Logged out successfully."})


@app.route("/products", methods=["GET"])
def get_products():
    user, error = get_authenticated_user()
    if error:
        return error

    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM products ORDER BY id ASC").fetchall()
    conn.close()
    products = [{"id": r["id"], "name": r["name"], "quantity": r["quantity"], "price": r["price"]} for r in rows]
    return jsonify(products)


@app.route("/add-product", methods=["POST"])
def add_product():
    user, error = require_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    qty = data.get("quantity")
    price = data.get("price")

    if not name:
        return jsonify({"success": False, "message": "Product name is required."}), 400

    try:
        qty_value = int(qty)
        price_value = float(price)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Quantity and price must be numeric values."}), 400

    if qty_value < 0 or price_value < 0:
        return jsonify({"success": False, "message": "Quantity and price cannot be negative."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, quantity, price) VALUES (?, ?, ?)",
        (name, qty_value, price_value),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Product added successfully!"})


@app.route("/add-vendor", methods=["POST"])
def add_vendor():
    user, error = require_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    name = str(data.get("vendor_name", "")).strip()
    contact = str(data.get("contact_details", "") or "").strip()
    category = str(data.get("supply_category", "") or "").strip()

    if not name:
        return jsonify({"success": False, "message": "Vendor name is required."}), 400

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO vendors (vendor_name, contact_details, supply_category) VALUES (?, ?, ?)",
        (name, contact, category),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Vendor '{name}' added successfully!"})


@app.route("/add-employee", methods=["POST"])
def add_employee():
    user, error = require_admin()
    if error:
        return error

    data = request.get_json(silent=True) or {}
    name = str(data.get("emp_name", "")).strip()
    emp_role = str(data.get("emp_role", "") or "").strip()
    phone = str(data.get("emp_phone", "") or "").strip()

    if not name:
        return jsonify({"success": False, "message": "Employee name is required."}), 400

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO employees (emp_name, emp_role, emp_phone) VALUES (?, ?, ?)",
        (name, emp_role, phone),
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Employee '{name}' added successfully!"})


@app.route("/export-excel", methods=["GET"])
def export_excel():
    user, error = require_admin()
    if error:
        return error

    data_type = request.args.get("type", "products").strip().lower()
    allowed_types = {"products": ("SELECT * FROM products ORDER BY id ASC", "Inventory", "inventory_master.xlsx"),
                     "vendors": ("SELECT * FROM vendors ORDER BY id ASC", "Vendors", "vendors_master.xlsx"),
                     "employees": ("SELECT * FROM employees ORDER BY id ASC", "Employees", "employees_master.xlsx")}

    if data_type not in allowed_types:
        return jsonify({"success": False, "message": "Invalid export type."}), 400

    query, sheet_name, download_name = allowed_types[data_type]
    conn = get_db_connection()
    df = pd.read_sql_query(query, conn)
    conn.close()

    out = io.BytesIO()
    with pd.ExcelWriter(out, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)

    out.seek(0)
    return send_file(
        out,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=download_name,
    )


@app.route("/import-excel", methods=["POST"])
def import_excel():
    user, error = require_admin()
    if error:
        return error

    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded!"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "message": "No file selected!"}), 400

    data_type = request.form.get("type", "products").strip().lower()
    if data_type not in {"products", "vendors", "employees"}:
        return jsonify({"success": False, "message": "Invalid import type."}), 400

    try:
        excel_data = file.read()
        df = pd.read_excel(io.BytesIO(excel_data))
    except Exception as exc:
        return jsonify({"success": False, "message": f"Error reading Excel file: {exc}"}), 400

    conn = get_db_connection()
    inserted_count = 0

    try:
        if data_type == "vendors":
            required_columns = {"vendor_name", "contact_details", "supply_category"}
            if not required_columns.issubset(df.columns):
                return jsonify({"success": False, "message": "Vendor Excel requires columns: vendor_name, contact_details, supply_category."}), 400
            for _, row in df.iterrows():
                conn.execute(
                    "INSERT INTO vendors (vendor_name, contact_details, supply_category) VALUES (?, ?, ?)",
                    (str(row["vendor_name"]), str(row.get("contact_details", "") or ""), str(row.get("supply_category", "") or "")),
                )
                inserted_count += 1
        elif data_type == "employees":
            required_columns = {"emp_name", "emp_role", "emp_phone"}
            if not required_columns.issubset(df.columns):
                return jsonify({"success": False, "message": "Employee Excel requires columns: emp_name, emp_role, emp_phone."}), 400
            for _, row in df.iterrows():
                conn.execute(
                    "INSERT INTO employees (emp_name, emp_role, emp_phone) VALUES (?, ?, ?)",
                    (str(row["emp_name"]), str(row.get("emp_role", "") or ""), str(row.get("emp_phone", "") or "")),
                )
                inserted_count += 1
        else:
            required_columns = {"name", "quantity", "price"}
            if not required_columns.issubset(df.columns):
                return jsonify({"success": False, "message": "Product Excel requires columns: name, quantity, price."}), 400
            for _, row in df.iterrows():
                qty_value = int(row["quantity"])
                price_value = float(row["price"])
                conn.execute(
                    "INSERT INTO products (name, quantity, price) VALUES (?, ?, ?)",
                    (str(row["name"]), qty_value, price_value),
                )
                inserted_count += 1

        conn.commit()
        return jsonify({"success": True, "message": f"{inserted_count} records bulk uploaded successfully to {data_type}!"})
    except Exception as exc:
        conn.rollback()
        return jsonify({"success": False, "message": f"Error processing file: {exc}"}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    print("Enterprise Backend Server Started on Port 5000...")
    app.run(port=5000, debug=True)