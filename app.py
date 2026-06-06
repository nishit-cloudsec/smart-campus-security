# Smart Campus Asset Manager - Flask App
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import db,cursor
import re
from datetime import datetime
from flask import flash
from scanner import scan_ports
from monitor import get_device_status
from risk_analyzer import get_risk
from datetime import datetime

# Utility functions for validation
def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False

    parts = ip.split(".")
    for part in parts:
        if int(part) > 255:
            return False
    return True

# MAC address validation
def is_valid_mac(mac):
    pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    return re.match(pattern, mac)

# Flask app setup
app = Flask(__name__)
app.secret_key = "smartcampus"

# Home route
@app.route('/')
def home():
    return redirect(url_for('login'))

# Admin creation route (for testing/demo purposes)
@app.route('/create-admin', methods=['GET', 'POST'])
def create_admin():
    secret_key = "supersecret123"

    if request.method == 'POST':
        key = request.form['key']

        if key != secret_key:
            return render_template("create_admin.html", error="Invalid Secret Key ❌")

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        query = "INSERT INTO USERS (username,email,password,role) VALUES (%s,%s,%s,%s)"
        values = (username, email, hashed_password, "admin")

        cursor.execute(query, values)
        db.commit()

        return render_template("create_admin.html", success="Admin created successfully! Redirecting to login...")

    return render_template('create_admin.html')

# User Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # ✅ Empty check
        if not all([username, email, password, confirm_password]):
            flash("❌ All fields are required!")
            return redirect(url_for('signup'))

        # 🔐 Password match check
        if password != confirm_password:
            flash("❌ Passwords do not match!")
            return redirect(url_for('signup'))

        # ✅ Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        role = 'user'

        query = "INSERT INTO USERS (username,email,password,role) VALUES (%s,%s,%s,%s)"
        values = (username, email, hashed_password, role)

        cursor.execute(query, values)
        db.commit()

        flash("✅ Account created successfully!")
        return redirect(url_for('login'))

    return render_template('signup.html')

# Admin/User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = "SELECT * FROM users WHERE username=%s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

# Admin Dashboard
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Fetch all assets
    cursor.execute("SELECT * FROM assets")
    assets = cursor.fetchall()

    total_devices = len(assets)

    # Active devices
    cursor.execute("SELECT COUNT(*) AS count FROM assets WHERE status='active'")
    active_devices = cursor.fetchone()['count']

    # Inactive devices
    cursor.execute("SELECT COUNT(*) AS count FROM assets WHERE status='inactive'")
    inactive_devices = cursor.fetchone()['count']

    # ✅ Safe alerts handling (NO CRASH)
    try:
        cursor.execute("SELECT COUNT(*) AS count FROM alerts WHERE severity='high'")
        result = cursor.fetchone()
        high_risk_alerts = result['count'] if result else 0
    except Exception as e:
        print("Alerts error:", e)
        high_risk_alerts = 0

    return render_template(
        'admin.html',
        assets=assets,
        total_devices=total_devices,
        active_devices=active_devices,
        inactive_devices=inactive_devices,
        high_risk_alerts=high_risk_alerts
    )

# Back to admin dashboard from user page
@app.route('/back_to_admin')
def back_to_admin():
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

# User Dashboard
@app.route('/user')
def user_dashboard():
    if session.get('role') in ['user', 'admin']:
        cursor.execute("SELECT * FROM assets")
        assets = cursor.fetchall()
        return render_template('user.html', assets=assets)
    return redirect(url_for('login'))

# User Report
@app.route('/user-report')
def user_report():
    if session.get('role') not in ['user', 'admin']:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM assets")
    assets = cursor.fetchall()

    reports = []
    report_id = 1

    for asset in assets:
        # 🔍 Scan Logic (same as admin)
        if asset['status'] == 'inactive':
            port = 22
            service = "SSH"
            risk = "High"
        elif asset['device_type'].lower() == 'server':
            port = 80
            service = "HTTP"
            risk = "Medium"
        else:
            port = 443
            service = "HTTPS"
            risk = "Low"

        reports.append({
            "id": f"R{str(report_id).zfill(3)}",
            "device_name": asset['device_name'],
            "ip": asset['ip_address'],
            "date": datetime.now().strftime("%d-%m-%Y"),
            "port": port,
            "service": service,
            "risk": risk
        })

        report_id += 1

    return render_template('user_report.html', reports=reports)

# Add Asset (Admin Only)
@app.route('/add_asset', methods=['GET', 'POST'])
def add_asset():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        device_name = request.form.get('device_name')
        device_type = request.form.get('device_type')
        ip_address = request.form.get('ip_address')
        mac_address = request.form.get('mac_address')
        location = request.form.get('location')
        status = request.form.get('status')

        # ✅ Empty field check
        if not all([device_name, device_type, ip_address, mac_address, location, status]):
            flash("❌ All fields are required!")
            return redirect(url_for('add_asset'))

        # ✅ IP validation
        if not is_valid_ip(ip_address):
            flash("❌ Invalid IP Address!")
            return redirect(url_for('add_asset'))

        # ✅ MAC validation
        if not is_valid_mac(mac_address):
            flash("❌ Invalid MAC Address!")
            return redirect(url_for('add_asset'))

        # ✅ Insert if valid
        query = """
        INSERT INTO assets (device_name, device_type, ip_address, mac_address, location, status)
        VALUES (%s,%s,%s,%s,%s,%s)
        """

        cursor.execute(query, (device_name, device_type, ip_address, mac_address, location, status))
        db.commit()

        flash("✅ Device Added Successfully!")
        return redirect(url_for('admin_dashboard'))

    return render_template('add_device.html')

# Delete Asset (Admin Only)
@app.route('/delete/<int:asset_id>')
def delete_asset(asset_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    cursor.execute("DELETE FROM assets WHERE id=%s", (asset_id,))
    db.commit()

    return redirect(url_for('admin_dashboard'))

# Edit Asset (Admin Only)
@app.route('/edit/<int:asset_id>', methods=['GET', 'POST'])
def edit_asset(asset_id):
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    # Fetch asset from DB
    cursor.execute("SELECT * FROM assets WHERE id=%s", (asset_id,))
    asset = cursor.fetchone()

    if not asset:
        return "Asset not found", 404

    if request.method == 'POST':
        device_name = request.form['device_name']
        device_type = request.form['device_type']
        ip_address = request.form['ip_address']
        mac_address = request.form['mac_address']
        location = request.form['location']
        status = request.form['status']

        query = """
        UPDATE assets 
        SET device_name=%s,
            device_type=%s,
            ip_address=%s,
            mac_address=%s,
            location=%s,
            status=%s
        WHERE id=%s
        """

        cursor.execute(query, (
            device_name,
            device_type,
            ip_address,
            mac_address,
            location,
            status,
            asset_id
        ))

        db.commit()

        return redirect(url_for('admin_dashboard'))
    return render_template('edit_device.html', asset=asset)

# Report Page (Admin and User)
@app.route('/report')
def report_page():

    if session.get('role') not in ['admin', 'user']:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM assets")
    assets = cursor.fetchall()

    reports = []
    report_id = 1

    for asset in assets:

        ip = asset['ip_address']

        try:
            print("Scanning IP:", ip)

            # Device Status
            status = get_device_status(ip)

            # Scan Ports
            scan_results = scan_ports(ip)

            print("Results:", scan_results)

            # If no ports found
            # If no ports found
            if not scan_results:

                reports.append({
                    "id": f"R{str(report_id).zfill(3)}",
                    "device_name": asset['device_name'],
                    "ip": ip,
                    "status": status,
                    "date": datetime.now().strftime("%d-%m-%Y"),

                    # FIXED VALUES
                    "port": "No Open Ports",
                    "service": "-",

                    "risk": "Low"
                })

                report_id += 1

            else:

                for result in scan_results:

                    reports.append({
                        "id": f"R{str(report_id).zfill(3)}",
                        "device_name": asset['device_name'],
                        "ip": ip,
                        "date": datetime.now().strftime("%d-%m-%Y"),
                        "port": result['port'],
                        "service": result['service'],
                        "risk": get_risk(result['port']),
                        "status": status
                    })

                    report_id += 1

        except Exception as e:
            print("Scan error:", e)

    return render_template('report_page.html', reports=reports)

# Admin/User Profile
@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']

        query="SELECT * FROM users WHERE username=%s"
        cursor.execute(query,(username,))
        users = cursor.fetchone()

        return render_template(
            'profile.html',
            username=username,
            email=users.get('email'),
            role=users.get('role')
        )

    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)